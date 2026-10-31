"""Command line: python -m vulngen --out ../data"""

from __future__ import annotations

import argparse
import shutil
import sys
import time
from datetime import date
from pathlib import Path

from .config import GenConfig
from .generate import generate


def main(argv: list[str] | None = None) -> int:
    d = GenConfig()
    p = argparse.ArgumentParser(prog="vulngen", description="Generate synthetic Tenable + Wiz data.")
    p.add_argument("--out", default="data", help="output directory (default: ./data)")
    p.add_argument("--seed", type=int, default=d.seed)
    p.add_argument("--start", type=date.fromisoformat, default=d.start, help="YYYY-MM-DD")
    p.add_argument("--days", type=int, default=d.days)
    p.add_argument("--tenable-assets", type=int, default=d.tenable_assets)
    p.add_argument("--wiz-assets", type=int, default=d.wiz_assets)
    p.add_argument("--tenable-findings", type=int, default=d.tenable_findings)
    p.add_argument("--wiz-findings", type=int, default=d.wiz_findings)
    p.add_argument("--no-gzip", action="store_true", help="write plain .ndjson")
    p.add_argument("--no-canaries", action="store_true")
    p.add_argument("--clean", action="store_true", help="delete --out before generating")
    a = p.parse_args(argv)

    cfg = GenConfig(
        seed=a.seed,
        start=a.start,
        days=a.days,
        tenable_assets=a.tenable_assets,
        wiz_assets=a.wiz_assets,
        tenable_findings=a.tenable_findings,
        wiz_findings=a.wiz_findings,
        gzip=not a.no_gzip,
        include_canaries=not a.no_canaries,
    )
    out = Path(a.out)
    if a.clean and out.exists():
        if not (out / "manifest.json").exists():
            print(f"refusing to --clean {out}: no manifest.json (not a vulngen output dir)", file=sys.stderr)
            return 2
        shutil.rmtree(out)
    t0 = time.perf_counter()
    try:
        generate(cfg, out)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    print(f"done in {time.perf_counter() - t0:.1f}s -> {out.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
