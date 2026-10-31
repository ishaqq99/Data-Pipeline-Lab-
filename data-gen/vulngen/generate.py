"""Orchestrates generation and writes daily NDJSON files + manifest.json.

Output layout (under --out, default ./data):

    tenable/tenable_vulns_YYYY-MM-DD.ndjson[.gz]
    wiz/wiz_vulnerability_findings_YYYY-MM-DD.ndjson[.gz]
    manifest.json      counts, per-file sha256, edge-case finding IDs, canary expectations

NDJSON = one JSON object per line, which Snowflake loads with
FILE_FORMAT = (TYPE = JSON) and no STRIP_OUTER_ARRAY.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import random
from collections import defaultdict
from datetime import timedelta
from pathlib import Path

from . import __version__
from .assets import build_tenable_assets, build_wiz_assets, rfc5737_hosts
from .canaries import build_canaries
from .catalog import CveFactory, build_tenable_catalog, build_wiz_catalog
from .config import GenConfig
from .findings import Finding, build_findings, deliveries
from .render import Clock, first_found_dt, render_tenable, render_wiz

FILE_PREFIX = {"tenable": "tenable_vulns", "wiz": "wiz_vulnerability_findings"}


def _dumps(rec: dict) -> bytes:
    return (json.dumps(rec, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def _write(path: Path, lines: list[bytes], use_gzip: bool) -> str:
    payload = b"".join(lines)
    if use_gzip:
        buf = io.BytesIO()
        # mtime=0 and empty filename make gzip output byte-for-byte reproducible
        with gzip.GzipFile(filename="", mode="wb", fileobj=buf, mtime=0, compresslevel=6) as gz:
            gz.write(payload)
        payload = buf.getvalue()
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def _edge_cases(source: str, f: Finding, rows: list[dict], cfg: GenConfig, clock: Clock) -> list[str]:
    tags: list[str] = []
    if f.backlog_days > 0 or first_found_dt(clock, f).date() < cfg.start:
        tags.append("first_found_before_window")
    if f.asset.dark_day is not None:
        tags.append("asset_stopped_scanning")
    if f.asset.born_day > 0:
        tags.append("asset_new_mid_window")
    if source == "tenable":
        states = [r["state"] for r in rows]
        if "REOPENED" in states:
            tags.append("reopened")
        if "FIXED" in states:
            tags.append("fixed")
        mods = {r["severity_modification"] for r in rows}
        if "RECASTED" in mods:
            tags.append("recasted")
        if "ACCEPTED" in mods:
            tags.append("risk_accepted")
        if len({r["severity"] for r in rows}) > 1:
            tags.append("severity_changed")
        if len({r["plugin"]["exploit_available"] for r in rows}) > 1:
            tags.append("exploit_flag_changed")
        if rows[0]["severity"] == "info":
            tags.append("info_severity")
        if f.asset.dark_day is not None and states[-1] != "FIXED":
            tags.append("open_on_stale_asset")
    else:
        statuses = [r["status"] for r in rows]
        if "RESOLVED" in statuses:
            tags.append("fixed")
            if statuses.index("RESOLVED") < len(statuses) - 1:
                tags.append("reopened")
        if "IGNORED" in statuses:
            tags.append("ignored")
        if "REJECTED" in statuses:
            tags.append("rejected")
        if len({r["severity"] for r in rows}) > 1:
            tags.append("severity_changed")
        if len({r["hasExploit"] for r in rows}) > 1:
            tags.append("exploit_flag_changed")
        if f.related_issues >= 100:
            tags.append("related_issues_100_plus")
        if rows[0]["fixedVersion"] is None:
            tags.append("no_fixed_version")
        if f.asset.dark_day is not None and statuses[-1] != "RESOLVED":
            tags.append("open_on_stale_asset")
    return tags


def generate(cfg: GenConfig, out_dir: Path, log=print) -> dict:
    cfg.validate()
    rng = random.Random(cfg.seed)
    clock = Clock(cfg.start)
    out_dir = Path(out_dir)

    # ---- catalogs, assets, findings (order of rng use matters for determinism) ----
    cves = CveFactory(rng)
    tn_catalog = build_tenable_catalog(rng, cves, cfg.days, n_exploit_flips=cfg.tenable_exploit_flip_plugins)
    wz_catalog = build_wiz_catalog(
        rng, cves, cfg.days, n_rerate=cfg.wiz_rerate_cves, n_exploit_flips=cfg.wiz_exploit_flip_cves
    )
    ips = rfc5737_hosts()[:-2]  # last two reserved for canaries
    tn_assets = build_tenable_assets(rng, cfg, ips)
    wz_assets = build_wiz_assets(rng, cfg)
    tn_findings = build_findings(rng, cfg, "tenable", tn_assets, tn_catalog, cfg.tenable_findings)
    wz_findings = build_findings(rng, cfg, "wiz", wz_assets, wz_catalog, cfg.wiz_findings)

    if cfg.include_canaries:
        c_tn_assets, c_wz_assets, c_tn, c_wz = build_canaries(cfg)
        tn_assets += c_tn_assets
        wz_assets += c_wz_assets
        tn_findings += c_tn
        wz_findings += c_wz

    manifest: dict = {
        "generator_version": __version__,
        "config": cfg.to_dict(),
        "window": {
            "start": cfg.start.isoformat(),
            "end": (cfg.start + timedelta(days=cfg.days - 1)).isoformat(),
        },
        "sources": {},
        "canaries": [],
    }

    for source, findings, assets, render in (
        ("tenable", tn_findings, tn_assets, render_tenable),
        ("wiz", wz_findings, wz_assets, render_wiz),
    ):
        src_dir = out_dir / source
        src_dir.mkdir(parents=True, exist_ok=True)
        by_day: dict[int, list[bytes]] = defaultdict(list)
        edge: dict[str, list[str]] = defaultdict(list)
        dup_rng = random.Random(f"{cfg.seed}-{source}-dups")  # independent stream
        total_rows = 0

        for f in findings:
            dels = deliveries(f)
            rows = [render(clock, f, d) for d in dels]
            for d, rec in zip(dels, rows, strict=True):
                line = _dumps(rec)
                by_day[d.day].append(line)
                total_rows += 1
                forced = f.force_dup_day is not None and d.day == f.force_dup_day
                random_dups = not f.canary
                if forced or (random_dups and dup_rng.random() < cfg.dup_within_file_rate):
                    by_day[d.day].append(line)
                    edge["duplicate_within_file"].append(f.id)
                    total_rows += 1
                if (
                    forced or (random_dups and dup_rng.random() < cfg.dup_next_day_rate)
                ) and d.day + 1 < cfg.days:
                    by_day[d.day + 1].append(line)  # stale copy re-delivered next day
                    edge["duplicate_next_day"].append(f.id)
                    total_rows += 1
            for tag in _edge_cases(source, f, rows, cfg, clock):
                edge[tag].append(f.id)
            if f.canary:
                last = rows[-1]
                manifest["canaries"].append(
                    {
                        "label": f.canary,
                        "source": source,
                        "finding_id": f.id,
                        "asset": f.asset.name,
                        "description": f.canary_note,
                        "first_found": last["first_found" if source == "tenable" else "firstDetectedAt"],
                        "final_row": {
                            k: last[k]
                            for k in (
                                ("state", "severity", "severity_modification", "last_found", "last_fixed")
                                if source == "tenable"
                                else (
                                    "status",
                                    "severity",
                                    "score",
                                    "lastDetectedAt",
                                    "resolvedAt",
                                    "hasExploit",
                                    "relatedIssueCount",
                                )
                            )
                            if k in last
                        },
                        "rows_delivered": len(rows),
                    }
                )

        files = []
        ext = ".ndjson.gz" if cfg.gzip else ".ndjson"
        for day in range(cfg.days):
            ds = (cfg.start + timedelta(days=day)).isoformat()
            path = src_dir / f"{FILE_PREFIX[source]}_{ds}{ext}"
            lines = by_day.get(day, [])
            files.append(
                {
                    "file": str(path.relative_to(out_dir)).replace("\\", "/"),
                    "date": ds,
                    "rows": len(lines),
                    "sha256": _write(path, lines, cfg.gzip),
                }
            )

        manifest["sources"][source] = {
            "assets": len(assets),
            "findings": len(findings),
            "rows": total_rows,
            "files": files,
            "edge_case_counts": {k: len(set(v)) for k, v in sorted(edge.items())},
            "edge_cases": {k: sorted(set(v)) for k, v in sorted(edge.items())},
        }
        log(
            f"{source:8s} assets={len(assets):5d} findings={len(findings):6d} rows={total_rows:7d} "
            f"files={len(files)}"
        )

    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest
