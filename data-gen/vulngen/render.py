"""Turn a (finding, delivery) pair into an API-shaped JSON record.

Shapes follow the public docs for Tenable `POST /vulns/export` chunks and the Wiz
`vulnerabilityFindings` GraphQL node. Field names are representative, not exhaustive.
Tenable omits keys that have no value; Wiz returns null. Timestamp formats differ
on purpose (Tenable has .000 milliseconds, Wiz does not).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, time, timedelta

from .catalog import WIZ_SEV, severity_from_cvss
from .config import SEVERITIES
from .findings import Delivery, Finding

SCAN_NS = uuid.UUID("0b8e1a1c-7d2f-4a7e-8f0b-1d5c3e9a2b40")


class Clock:
    def __init__(self, start):
        self.base = datetime.combine(start, time(0), tzinfo=UTC)

    def at(self, day: int, minute: int) -> datetime:
        return self.base + timedelta(days=day, minutes=minute)


def _scan_dt(clock: Clock, f: Finding, day: int) -> datetime:
    # deterministic per-day jitter of 0-24 minutes around the asset's scan slot
    return clock.at(day, f.asset.scan_minute + (day * 7) % 25)


def tenable_ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def wiz_ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def first_found_dt(clock: Clock, f: Finding) -> datetime:
    first_day = f.asset.scan_days[f.spans[0][0]]
    return _scan_dt(clock, f, first_day) - timedelta(days=f.backlog_days)


def render_tenable(clock: Clock, f: Finding, d: Delivery) -> dict:
    p = f.vuln
    a = f.asset
    sev = p.severity
    mod = "NONE"
    if f.recast_idx is not None and f.recast_to and d.idx >= f.recast_idx:
        sev, mod = f.recast_to, "RECASTED"
    if f.accept_idx is not None and d.idx >= f.accept_idx:
        mod = "ACCEPTED"
    exploit = p.exploit_available or (p.exploit_flip_day is not None and d.day >= p.exploit_flip_day)
    scan_dt = _scan_dt(clock, f, d.day)

    plugin = {
        "id": p.id,
        "name": p.name,
        "family": p.family,
        "type": p.plugin_type,
        "publication_date": f"{p.publication_date}T00:00:00Z",
        "exploit_available": exploit,
        "has_patch": p.fixed_version is not None,
    }
    if p.cvss3_base_score is not None:
        plugin["cvss3_base_score"] = p.cvss3_base_score
    if p.vpr_score is not None:
        plugin["vpr"] = {"score": p.vpr_score}
    if p.cves:
        plugin["cve"] = list(p.cves)
    if p.fixed_version:
        plugin["solution"] = f"Upgrade {p.package} to version {p.fixed_version} or later."

    rec = {
        "asset": {"uuid": a.id, **a.attrs, "tracked": True},
        "finding_id": f.id,
        "plugin": plugin,
        "port": {"port": f.port[0], "protocol": f.port[1], "service": f.port[2]},
        "scan": {
            "uuid": str(uuid.uuid5(SCAN_NS, f"{a.id}:{d.day}")),
            "started_at": tenable_ts(scan_dt - timedelta(minutes=20)),
            "completed_at": tenable_ts(scan_dt),
        },
        "severity": sev,
        "severity_id": SEVERITIES.index(sev),
        "severity_default_id": SEVERITIES.index(p.severity),
        "severity_modification": mod,
        "state": d.state,
        "first_found": tenable_ts(first_found_dt(clock, f)),
        "last_found": tenable_ts(_scan_dt(clock, f, d.last_seen_day)),
        "indexed": tenable_ts(scan_dt + timedelta(hours=2)),
    }
    if d.last_fixed_day is not None:
        rec["last_fixed"] = tenable_ts(_scan_dt(clock, f, d.last_fixed_day))
    if p.package:
        rec["output"] = (
            f"\n  - Installed package : {p.package}-{p.installed_version}\n"
            f"  - Fixed package     : {p.package}-{p.fixed_version}\n"
        )
    return rec


def render_wiz(clock: Clock, f: Finding, d: Delivery) -> dict:
    v = f.vuln
    score = v.score
    if v.rerate_day is not None and v.rerated_score is not None and d.day >= v.rerate_day:
        score = v.rerated_score
    sev = WIZ_SEV[severity_from_cvss(score)]
    has_exploit = v.has_exploit or (v.exploit_flip_day is not None and d.day >= v.exploit_flip_day)

    if d.state == "FIXED":
        status = "RESOLVED"
    elif f.status_change and f.status_idx is not None and d.idx >= f.status_idx:
        status = f.status_change
    else:
        status = "OPEN"

    scan_dt = _scan_dt(clock, f, d.day)
    loc = f"/usr/lib/{v.package}" if f.asset.attrs["type"] != "CONTAINER_IMAGE" else f"/app/lib/{v.package}"
    return {
        "id": f.id,
        "portalUrl": f"https://app.wiz.example.com/findings/vulnerability-findings#~(entity~'{f.id})",
        "name": v.cve,
        "CVEDescription": v.description,
        "CVSSSeverity": sev,
        "score": score,
        "severity": sev,
        "status": status,
        "firstDetectedAt": wiz_ts(first_found_dt(clock, f)),
        "lastDetectedAt": wiz_ts(_scan_dt(clock, f, d.last_seen_day)),
        "resolvedAt": wiz_ts(scan_dt) if d.state == "FIXED" else None,
        "updatedAt": wiz_ts(scan_dt + timedelta(minutes=30)),
        "hasExploit": has_exploit,
        "hasCisaKevExploit": v.has_kev,
        "detailedName": v.package,
        "version": v.version,
        "fixedVersion": v.fixed_version,
        "detectionMethod": "PACKAGE",
        "locationPath": loc,
        "relatedIssueCount": f.related_issues,
        "vulnerableAsset": {"id": f.asset.id, **f.asset.attrs},
    }
