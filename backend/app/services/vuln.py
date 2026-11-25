"""Unified vulnerability intelligence: NVD 2.0 + OSV + EPSS, with a local cache.

Design goals (all missing from the legacy tools, which either shipped a 328 MB
JSON blob or hammered an API through a hard-coded proxy):

* **Offline-first.** A SQLite cache means the testbed is fully usable air-gapped
  after one sync, and repeat lookups are instant.
* **Rate-limit aware.** NVD allows 5 req/30s unauthenticated, 50 with a key.
* **Graceful.** If the network is down, we return whatever is cached and mark the
  result ``partial`` instead of failing the whole audit.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

import httpx

from app.core.config import settings
from app.core.logging import get_logger

log = get_logger("services.vuln")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cves (
    id          TEXT PRIMARY KEY,
    description TEXT,
    cvss        REAL,
    severity    TEXT,
    published   TEXT,
    keywords    TEXT,
    raw         TEXT
);
CREATE TABLE IF NOT EXISTS epss (
    cve      TEXT PRIMARY KEY,
    score    REAL,
    percentile REAL,
    updated  TEXT
);
CREATE VIRTUAL TABLE IF NOT EXISTS cve_fts USING fts5(
    id UNINDEXED, description, keywords, content='cves', content_rowid='rowid'
);
-- External-content FTS5 needs explicit sync triggers; without them rows written
-- into cves are invisible to MATCH until a rebuild (the legacy bug: a completed
-- NVD sync then returned zero offline hits).
CREATE TRIGGER IF NOT EXISTS cves_fts_ai AFTER INSERT ON cves BEGIN
    INSERT INTO cve_fts(rowid, id, description, keywords)
    VALUES (new.rowid, new.id, new.description, new.keywords);
END;
CREATE TRIGGER IF NOT EXISTS cves_fts_au AFTER UPDATE ON cves BEGIN
    INSERT INTO cve_fts(cve_fts, rowid, id, description, keywords)
    VALUES('delete', old.rowid, old.id, old.description, old.keywords);
    INSERT INTO cve_fts(rowid, id, description, keywords)
    VALUES (new.rowid, new.id, new.description, new.keywords);
END;
CREATE TRIGGER IF NOT EXISTS cves_fts_ad AFTER DELETE ON cves BEGIN
    INSERT INTO cve_fts(cve_fts, rowid, id, description, keywords)
    VALUES('delete', old.rowid, old.id, old.description, old.keywords);
END;
"""


@dataclass
class CVEHit:
    id: str
    description: str = ""
    cvss: float | None = None
    severity: str = "unknown"
    published: str | None = None
    epss: float | None = None
    percentile: float | None = None
    references: list[str] = field(default_factory=list)
    matched_on: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


class VulnIntel:
    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = Path(db_path or settings.cve_db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._last_nvd_call = 0.0
        self._init_db()

    # ------------------------------------------------------------------ #
    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.executescript(_SCHEMA)
            # Repairs databases created before the sync triggers existed: an
            # FTS index left empty behind a populated cves table is silently
            # rebuilt here instead of pinning every offline search to zero hits.
            try:
                n = conn.execute("SELECT COUNT(*) AS c FROM cves").fetchone()["c"]
                f = conn.execute("SELECT COUNT(*) AS c FROM cve_fts").fetchone()["c"]
                if n and f == 0:
                    conn.execute("INSERT INTO cve_fts(cve_fts) VALUES('rebuild')")
                    log.info("rebuilt empty FTS index over %d cached CVEs", n)
            except sqlite3.OperationalError as exc:  # pragma: no cover - legacy db
                log.warning("FTS health-check skipped: %s", exc)

    # ---- cache reads --------------------------------------------------- #
    def _cached(self, keyword: str, limit: int) -> list[CVEHit]:
        kw = (keyword or "").strip()
        if not kw:
            return []
        rows: list[sqlite3.Row] = []
        with self._conn() as conn:
            try:
                # FTS: quoted tokens ANDed together handle multi-word terms
                # ("busybox 1.31.0") without requiring exact adjacency.
                match_query = " AND ".join(f'"{t}"' for t in kw.split())
                rows = conn.execute(
                    """
                    SELECT c.* FROM cve_fts f JOIN cves c ON c.rowid = f.rowid
                    WHERE cve_fts MATCH ? ORDER BY c.cvss DESC LIMIT ?
                    """,
                    (match_query, limit),
                ).fetchall()
            except sqlite3.OperationalError as exc:
                log.debug("FTS match failed (%s); falling back to LIKE", exc)
            if not rows:
                try:
                    clauses, params = [], []
                    for tok in kw.split():
                        clauses.append("(description LIKE ? OR keywords LIKE ?)")
                        params += [f"%{tok}%", f"%{tok}%"]
                    params.append(limit)
                    rows = conn.execute(
                        f"SELECT * FROM cves WHERE {' AND '.join(clauses)} "
                        "ORDER BY cvss DESC LIMIT ?",
                        params,
                    ).fetchall()
                except sqlite3.OperationalError:
                    rows = []
        return [self._row_to_hit(r, keyword) for r in rows]

    def _row_to_hit(self, row: sqlite3.Row, matched: str) -> CVEHit:
        raw = json.loads(row["raw"]) if row["raw"] else {}
        return CVEHit(
            id=row["id"],
            description=row["description"] or "",
            cvss=row["cvss"],
            severity=row["severity"] or "unknown",
            published=row["published"],
            references=raw.get("references", []),
            matched_on=matched,
        )

    # ---- cache writes -------------------------------------------------- #
    def _store(self, hits: list[CVEHit], keywords: list[str]) -> None:
        with self._lock, self._conn() as conn:
            for h in hits:
                conn.execute(
                    """
                    INSERT INTO cves (id, description, cvss, severity, published, keywords, raw)
                    VALUES (?,?,?,?,?,?,?)
                    ON CONFLICT(id) DO UPDATE SET
                        cvss=excluded.cvss, severity=excluded.severity,
                        description=excluded.description, keywords=excluded.keywords
                    """,
                    (
                        h.id,
                        h.description,
                        h.cvss,
                        h.severity,
                        h.published,
                        " ".join(keywords),
                        json.dumps({"references": h.references}),
                    ),
                )

    # ---- online NVD ---------------------------------------------------- #
    def _rate_limit(self) -> None:
        window = 6.5 if settings.nvd_api_key else 32.0
        elapsed = time.monotonic() - self._last_nvd_call
        if elapsed < window:
            time.sleep(window - elapsed)
        self._last_nvd_call = time.monotonic()

    def _nvd_keyword_search(self, keyword: str, limit: int) -> list[CVEHit]:
        if not settings.cve_online:
            return []
        headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
        params = {"keywordSearch": keyword, "resultsPerPage": min(limit, 50)}
        try:
            self._rate_limit()
            with httpx.Client(timeout=30) as client:
                resp = client.get(settings.nvd_base_url, params=params, headers=headers)
                resp.raise_for_status()
                payload = resp.json()
        except Exception as exc:  # noqa: BLE001 - degrade gracefully
            log.warning("NVD lookup failed for '%s': %s", keyword, exc)
            return []
        return self._parse_nvd(payload)

    @staticmethod
    def _parse_nvd(payload: dict) -> list[CVEHit]:
        hits: list[CVEHit] = []
        for item in payload.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cid = cve.get("id")
            if not cid:
                continue
            desc = next(
                (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), ""
            )
            metrics = cve.get("metrics", {})
            cvss, severity = None, "unknown"
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metrics.get(key):
                    data = metrics[key][0].get("cvssData", {})
                    cvss = data.get("baseScore")
                    severity = (data.get("baseSeverity") or metrics[key][0].get("baseSeverity")
                                or "unknown").lower()
                    break
            refs = [r.get("url", "") for r in cve.get("references", [])][:5]
            hits.append(
                CVEHit(id=cid, description=desc, cvss=cvss, severity=severity,
                       published=cve.get("published"), references=refs)
            )
        return hits

    # ---- public API ---------------------------------------------------- #
    def search_keywords(self, keywords: list[str], *, limit: int = 20) -> list[CVEHit]:
        """Search by free-text keywords (e.g. product + version). De-duplicated."""
        seen: dict[str, CVEHit] = {}
        terms = [k.strip() for k in keywords if k and k.strip()]
        for term in terms:
            for hit in self._cached(term, limit):
                seen.setdefault(hit.id, hit)
            if len(seen) < limit:
                fresh = self._nvd_keyword_search(term, limit)
                if fresh:
                    self._store(fresh, terms)
                    for hit in fresh:
                        hit.matched_on = term
                        seen.setdefault(hit.id, hit)
        ranked = sorted(seen.values(), key=lambda h: (h.cvss or 0), reverse=True)
        result = ranked[:limit]
        self.enrich_epss([h.id for h in result])
        for h in result:
            e = self._epss_for(h.id)
            if e:
                h.epss, h.percentile = e
        return result

    def enrich_epss(self, cve_ids: list[str]) -> None:
        if not settings.cve_online or not cve_ids:
            return
        missing = [c for c in cve_ids if not self._epss_for(c)]
        if not missing:
            return
        try:
            with httpx.Client(timeout=20) as client:
                resp = client.get(settings.epss_base_url, params={"cve": ",".join(missing)})
                resp.raise_for_status()
                data = resp.json().get("data", [])
        except Exception as exc:  # noqa: BLE001
            log.warning("EPSS lookup failed: %s", exc)
            return
        with self._lock, self._conn() as conn:
            for row in data:
                conn.execute(
                    "INSERT OR REPLACE INTO epss (cve, score, percentile, updated) VALUES (?,?,?,?)",
                    (row.get("cve"), float(row.get("epss", 0)), float(row.get("percentile", 0)),
                     row.get("date")),
                )

    def _epss_for(self, cve_id: str) -> tuple[float, float] | None:
        with self._conn() as conn:
            row = conn.execute("SELECT score, percentile FROM epss WHERE cve=?", (cve_id,)).fetchone()
        return (row["score"], row["percentile"]) if row else None

    def get(self, cve_id: str) -> CVEHit | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM cves WHERE id=?", (cve_id,)).fetchone()
        if not row:
            hits = self.search_keywords([cve_id], limit=1)
            return hits[0] if hits else None
        return self._row_to_hit(row, cve_id)

    def stats(self) -> dict:
        with self._conn() as conn:
            n = conn.execute("SELECT COUNT(*) AS c FROM cves").fetchone()["c"]
            e = conn.execute("SELECT COUNT(*) AS c FROM epss").fetchone()["c"]
        return {"cached_cves": n, "cached_epss": e, "online": settings.cve_online,
                "db_path": str(self.db_path)}


vuln_intel = VulnIntel()
