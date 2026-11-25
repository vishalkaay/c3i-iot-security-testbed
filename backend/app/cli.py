"""Command-line interface: ``c3i-iot <command>``.

Commands:
  serve      run the API (uvicorn)
  seed       create the database and bootstrap admin
  demo       seed + create a demo engagement with an authorized scope
  doctor     print host capabilities and dependency status
  sync-cve   warm the local vulnerability cache with a seed keyword list
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Allow running as `python -m app.cli` from the backend dir.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.main import bootstrap  # noqa: E402


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from app.core.config import settings

    uvicorn.run(
        "app.main:app",
        host=args.host or settings.host,
        port=args.port or settings.port,
        reload=args.reload,
        log_level=settings.log_level.lower(),
    )
    return 0


def cmd_seed(_: argparse.Namespace) -> int:
    bootstrap()
    print("Database initialised and bootstrap admin ensured.")
    return 0


def cmd_demo(_: argparse.Namespace) -> int:
    bootstrap()
    from app.core.database import SessionLocal
    from app.models import Engagement, EngagementStatus

    db = SessionLocal()
    try:
        if db.query(Engagement).count() == 0:
            eng = Engagement(
                name="Demo Engagement",
                client="C3i Hub (internal)",
                description="Sample engagement for UI exploration. Not authorized for invasive tests.",
                status=EngagementStatus.DRAFT.value,
                authorized_targets=["192.168.1.0/24", "AA:BB:CC:*"],
            )
            db.add(eng)
            db.commit()
            print(f"Created demo engagement {eng.id}")
        else:
            print("Engagements already present; nothing to do.")
    finally:
        db.close()
    return 0


def cmd_doctor(_: argparse.Namespace) -> int:
    bootstrap()
    from app.plugins.capabilities import CAPABILITIES, describe_all
    from app.services.vuln import vuln_intel

    print("\n== Host capabilities ==")
    for cap in describe_all(list(CAPABILITIES.keys())):
        mark = "OK " if cap["available"] else "-- "
        print(f"  [{mark}] {cap['id']:<22} {cap['label']}"
              + (f"   ({cap['hint']})" if not cap["available"] else ""))
    print("\n== Vulnerability intelligence ==")
    for k, v in vuln_intel.stats().items():
        print(f"  {k}: {v}")
    return 0


def cmd_sync_cve(_: argparse.Namespace) -> int:
    bootstrap()
    from app.services.vuln import vuln_intel

    seeds = [
        "openssl", "openssh", "busybox", "dropbear", "lighttpd", "dnsmasq",
        "u-boot", "mosquitto", "curl", "linux kernel", "bluetooth", "bluez",
    ]
    total = 0
    for kw in seeds:
        hits = vuln_intel.search_keywords([kw], limit=20)
        print(f"  {kw}: {len(hits)} cached")
        total += len(hits)
    print(f"\nCached {total} CVE records. Stats: {vuln_intel.stats()}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="c3i-iot", description="C3i Hub IoT Security Testbed")
    sub = parser.add_subparsers(dest="command", required=True)

    p_serve = sub.add_parser("serve", help="run the API")
    p_serve.add_argument("--host", default=None)
    p_serve.add_argument("--port", type=int, default=None)
    p_serve.add_argument("--reload", action="store_true")
    p_serve.set_defaults(func=cmd_serve)

    sub.add_parser("seed", help="create DB + admin").set_defaults(func=cmd_seed)
    sub.add_parser("demo", help="seed + demo engagement").set_defaults(func=cmd_demo)
    sub.add_parser("doctor", help="print capabilities").set_defaults(func=cmd_doctor)
    sub.add_parser("sync-cve", help="warm the CVE cache").set_defaults(func=cmd_sync_cve)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
