"""Canary findings: hand-built, fixed IDs and dates, for exact SLA / state tests in Phase 3.

Canary assets are scanned every day, so scan index == day offset from cfg.start.
IDs are uuid5 values, so they are identical for every seed.
"""

from __future__ import annotations

import uuid

from .assets import DOMAIN, Asset
from .catalog import WIZ_SEV, TenablePlugin, WizVuln, severity_from_cvss
from .findings import Finding

NS = uuid.UUID("6f1c2a52-0d3e-4c55-9a51-7b0d6c1e2f30")  # arbitrary fixed namespace


def cid(label: str) -> str:
    return str(uuid.uuid5(NS, label))


def _plugin(n: int, name: str, score: float | None, exploit: bool, flip: int | None = None) -> TenablePlugin:
    sev = severity_from_cvss(score)
    return TenablePlugin(
        id=999_000 + n,
        name=f"Canary {name}",
        family="General",
        platform="any",
        severity=sev,
        cvss3_base_score=score,
        vpr_score=None if score is None else round(min(10.0, score - 0.4), 1),
        exploit_available=exploit,
        cves=[] if score is None else [f"CVE-2026-{99900 + n}"],
        package=None if score is None else "canarypkg",
        installed_version="1.0.0",
        fixed_version=None if score is None else "1.0.1",
        publication_date="2026-01-15",
        plugin_type="local",
        exploit_flip_day=flip,
    )


def _wiz(
    n: int,
    score: float,
    exploit: bool,
    rerate: float | None = None,
    rerate_day: int | None = None,
    fixed: str | None = "2.0.1",
) -> WizVuln:
    return WizVuln(
        cve=f"CVE-2026-{99950 + n}",
        package="canary-lib",
        platform="any",
        version="2.0.0",
        fixed_version=fixed,
        score=score,
        severity=WIZ_SEV[severity_from_cvss(score)],
        has_exploit=exploit,
        has_kev=False,
        description=f"Canary vulnerability {n}.",
        rerate_day=rerate_day,
        rerated_score=rerate,
    )


def build_canaries(cfg) -> tuple[list[Asset], list[Asset], list[Finding], list[Finding]]:
    days = cfg.days
    tn1 = Asset(
        "tenable",
        cid("asset-canary-tn-01"),
        "canary-tn-01",
        "linux",
        {
            "hostname": "canary-tn-01",
            "fqdn": f"canary-tn-01.{DOMAIN}",
            "ipv4": "203.0.113.253",
            "operating_system": ["Linux Kernel 6.8 on Ubuntu 24.04"],
            "device_type": "general-purpose",
        },
        scan_days=list(range(days)),
        scan_minute=120,
        is_canary=True,
    )
    tn2 = Asset(
        "tenable",
        cid("asset-canary-tn-02"),
        "canary-tn-02",
        "linux",
        {
            "hostname": "canary-tn-02",
            "fqdn": f"canary-tn-02.{DOMAIN}",
            "ipv4": "203.0.113.254",
            "operating_system": ["Red Hat Enterprise Linux 9"],
            "device_type": "general-purpose",
        },
        dark_day=120,
        scan_days=list(range(120)),
        scan_minute=125,
        is_canary=True,
    )
    wz1 = Asset(
        "wiz",
        cid("asset-canary-wz-01"),
        "vm-canary-0001",
        "linux",
        {
            "type": "VIRTUAL_MACHINE",
            "name": "vm-canary-0001",
            "cloudPlatform": "Azure",
            "subscriptionName": "sub-lab-canary-01",
            "subscriptionExternalId": cid("sub-canary-01"),
            "region": "westus2",
            "operatingSystem": "Ubuntu 24.04",
        },
        scan_days=list(range(days)),
        scan_minute=180,
        is_canary=True,
    )

    def tf(label, asset, plugin, spans, note, **kw) -> Finding:
        return Finding(
            "tenable", cid(f"tenable-{label}"), asset, plugin, spans, canary=label, canary_note=note, **kw
        )

    def wf(label, vuln, spans, note, **kw) -> Finding:
        return Finding("wiz", cid(f"wiz-{label}"), wz1, vuln, spans, canary=label, canary_note=note, **kw)

    tenable = [
        tf(
            "TN-C1",
            tn1,
            _plugin(1, "Critical Never Fixed", 9.8, True),
            [(5, None)],
            "critical, first found day 5, never fixed, exploit available",
        ),
        tf(
            "TN-C2",
            tn1,
            _plugin(2, "High Fixed", 7.5, False),
            [(10, 45)],
            "high, found day 10, FIXED day 45 (last_found day 44)",
        ),
        tf(
            "TN-C3",
            tn1,
            _plugin(3, "Medium Reopened", 5.3, False),
            [(12, 33), (60, None)],
            "medium, found day 12, fixed day 33, REOPENED day 60, open at end",
        ),
        tf(
            "TN-C4",
            tn1,
            _plugin(4, "High Recast", 8.1, False),
            [(15, None)],
            "high found day 15, RECASTED to medium from day 31",
            recast_to="medium",
            recast_idx=31,
        ),
        tf(
            "TN-C5",
            tn1,
            _plugin(5, "Critical Accepted", 9.1, True),
            [(20, None)],
            "critical found day 20, risk ACCEPTED from day 40",
            accept_idx=40,
        ),
        tf("TN-C6", tn1, _plugin(6, "Low Open", 3.1, False), [(25, None)], "low, open (no SLA)"),
        tf("TN-C7", tn1, _plugin(7, "Info Open", None, False), [(0, None)], "info, open (no SLA)"),
        tf(
            "TN-C8",
            tn2,
            _plugin(8, "High Stale Asset", 7.8, False),
            [(30, None)],
            "high on asset that stops being scanned after day 119; stays OPEN, last_found day 119",
        ),
        tf(
            "TN-C9",
            tn1,
            _plugin(9, "Critical Backlog", 9.0, False),
            [(0, 70)],
            "critical, first_found 90 days before window start, FIXED day 70",
            backlog_days=90,
        ),
        tf(
            "TN-C10",
            tn1,
            _plugin(10, "Medium Exploit Flip", 6.5, False, flip=80),
            [(50, None)],
            "medium found day 50, exploit_available false -> true on day 80",
        ),
    ]
    wiz = [
        wf("WZ-C1", _wiz(1, 9.8, True), [(5, None)], "CRITICAL 9.8, hasExploit, open from day 5"),
        wf("WZ-C2", _wiz(2, 7.5, False), [(10, 40)], "HIGH 7.5, found day 10, RESOLVED day 40"),
        wf(
            "WZ-C3",
            _wiz(3, 5.3, False),
            [(12, None)],
            "MEDIUM, found day 12, IGNORED from day 30",
            status_change="IGNORED",
            status_idx=30,
        ),
        wf(
            "WZ-C4",
            _wiz(4, 8.1, False),
            [(14, None)],
            "HIGH, found day 14, REJECTED (false positive) day 20",
            status_change="REJECTED",
            status_idx=20,
        ),
        wf(
            "WZ-C5",
            _wiz(5, 6.5, False, rerate=9.1, rerate_day=50),
            [(16, None)],
            "MEDIUM 6.5 found day 16, re-rated to CRITICAL 9.1 from day 50",
        ),
        wf("WZ-C6", _wiz(6, 7.5, False), [(18, None)], "HIGH, 250 related issues", related_issues=250),
        wf(
            "WZ-C7",
            _wiz(7, 7.5, False),
            [(22, None)],
            "HIGH 7.5 open; day 60 row duplicated in its own file AND re-sent (stale) in day 61 file",
            force_dup_day=60,
        ),
        wf("WZ-C8", _wiz(8, 2.7, False, fixed=None), [(25, None)], "LOW, open, no fixed version"),
    ]
    return [tn1, tn2], [wz1], tenable, wiz
