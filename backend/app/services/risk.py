"""Severity normalisation, CVSS->severity mapping, and risk scoring."""

from __future__ import annotations

# CVSS v3 qualitative ratings.
CVSS_BANDS = [
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
    (0.0, "info"),
]


def cvss_to_severity(score: float | None) -> str:
    if score is None:
        return "info"
    for threshold, label in CVSS_BANDS:
        if score >= threshold:
            return label
    return "info"


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_WEIGHT = {"critical": 10.0, "high": 7.0, "medium": 4.0, "low": 1.5, "info": 0.2}


def worst(a: str, b: str) -> str:
    return a if SEVERITY_ORDER.get(a, 9) <= SEVERITY_ORDER.get(b, 9) else b


def engagement_risk_score(findings: list[dict]) -> float:
    """A 0-100 roll-up: weighted severities with a diminishing-returns curve."""
    if not findings:
        return 0.0
    weights = [SEVERITY_WEIGHT.get(f.get("severity", "info"), 0.2) for f in findings]
    # Criticals dominate; extra findings add less and less.
    weights.sort(reverse=True)
    total = sum(w * (0.85**i) for i, w in enumerate(weights))
    return round(min(100.0, total * 6.0), 1)


def summary_counts(findings: list[dict]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
    return counts
