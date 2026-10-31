"""Finding lifecycles.

A finding lives on one asset and is only observable on that asset's scan days.
Its lifecycle is a list of *spans* expressed as indexes into asset.scan_days:

    [(start_idx, end_idx_or_None), ...]

- Every scan index inside a span delivers the finding as OPEN (first span) or
  REOPENED (later spans).
- If end_idx is not None, the scan at end_idx delivers it as FIXED.
- end_idx None means still open at the end of the window (or the asset went dark).
"""

from __future__ import annotations

import bisect
import itertools
import random
from dataclasses import dataclass, field

from .assets import Asset, rng_uuid
from .catalog import TenablePlugin, WizVuln, severity_from_cvss
from .config import SEVERITIES, GenConfig

TENABLE_SEV_WEIGHTS = [0.12, 0.08, 0.38, 0.30, 0.12]  # info, low, medium, high, critical
WIZ_SEV_WEIGHTS = [0.0, 0.10, 0.42, 0.33, 0.15]
REMOTE_PORTS = {
    "linux": [
        (443, "TCP", "www"),
        (80, "TCP", "www"),
        (22, "TCP", "ssh"),
        (8443, "TCP", "www"),
        (161, "UDP", "snmp"),
    ],
    "windows": [(443, "TCP", "www"), (80, "TCP", "www"), (3389, "TCP", "msrdp"), (445, "TCP", "cifs")],
}
RECAST = {"critical": ["high"], "high": ["medium", "critical"], "medium": ["low", "high"], "low": ["medium"]}


@dataclass
class Finding:
    source: str
    id: str
    asset: Asset
    vuln: TenablePlugin | WizVuln
    spans: list[tuple[int, int | None]]
    backlog_days: int = 0  # > 0: first found this many days before the first scan
    port: tuple[int, str, str] = (0, "TCP", "general")
    recast_to: str | None = None
    recast_idx: int | None = None
    accept_idx: int | None = None
    status_change: str | None = None  # IGNORED | REJECTED (Wiz)
    status_idx: int | None = None
    related_issues: int = 0
    canary: str | None = None
    canary_note: str = ""
    force_dup_day: int | None = None  # canary: duplicate this day's row (within file + next day)


@dataclass
class Delivery:
    day: int  # day index the row is delivered
    idx: int  # scan index on the asset
    state: str  # OPEN | REOPENED | FIXED
    last_seen_day: int
    last_fixed_day: int | None


@dataclass
class _Index:
    by_key: dict = field(default_factory=dict)

    def add(self, key, item):
        self.by_key.setdefault(key, []).append(item)

    def pick(self, rng, platform, sev):
        pool = self.by_key.get((platform, sev))
        if not pool:
            return None
        return rng.choice(pool)


def deliveries(f: Finding) -> list[Delivery]:
    s_days = f.asset.scan_days
    out: list[Delivery] = []
    last_fixed: int | None = None
    for n, (start, end) in enumerate(f.spans):
        stop = end if end is not None else len(s_days)
        for idx in range(start, stop):
            out.append(Delivery(s_days[idx], idx, "REOPENED" if n > 0 else "OPEN", s_days[idx], last_fixed))
        if end is not None and end < len(s_days):
            last_fixed = s_days[end]
            out.append(Delivery(s_days[end], end, "FIXED", s_days[end - 1], last_fixed))
    return out


def _draw_spans(
    rng: random.Random, cfg: GenConfig, i0: int, n_scans: int, sev: str, interval: int, force_open: bool
) -> list[tuple[int, int | None]]:
    if force_open or rng.random() < cfg.never_fixed_rate:
        return [(i0, None)]
    mean = cfg.mean_days_to_fix[sev]
    k = max(1, round(rng.expovariate(1 / mean) / interval))
    end = i0 + k
    if end >= n_scans:
        return [(i0, None)]
    spans: list[tuple[int, int | None]] = [(i0, end)]
    if rng.random() < cfg.reopen_rate:
        reopen = end + rng.randint(2, 6)
        if reopen < n_scans:
            k2 = max(1, round(rng.expovariate(1 / mean) / interval))
            end2 = reopen + k2
            spans.append((reopen, end2 if end2 < n_scans else None))
    return spans


def _later_open_idx(rng: random.Random, spans, n_scans: int) -> int | None:
    """A random scan index, after first detection, at which the finding is still open."""
    i0 = spans[0][0]
    candidates = []
    for s, e in spans:
        candidates.extend(i for i in range(s, e if e is not None else n_scans) if i > i0)
    return rng.choice(candidates) if candidates else None


def build_findings(
    rng: random.Random, cfg: GenConfig, source: str, assets: list[Asset], catalog: list, n: int
) -> list[Finding]:
    interval = cfg.tenable_scan_interval if source == "tenable" else cfg.wiz_scan_interval
    sev_weights = TENABLE_SEV_WEIGHTS if source == "tenable" else WIZ_SEV_WEIGHTS
    cum_sev = list(itertools.accumulate(sev_weights))
    cum_assets = list(itertools.accumulate(a.weight for a in assets))

    index = _Index()
    for v in catalog:
        sev = v.severity if source == "tenable" else severity_from_cvss(v.score)
        plats = ["linux", "windows"] if v.platform == "any" else [v.platform]
        for p in plats:
            index.add((p, sev), v)

    used: set = set()
    findings: list[Finding] = []
    attempts = 0
    while len(findings) < n and attempts < n * 30:
        attempts += 1
        asset = assets[bisect.bisect_right(cum_assets, rng.random() * cum_assets[-1])]
        sev = SEVERITIES[bisect.bisect_right(cum_sev, rng.random() * cum_sev[-1])]
        vuln = index.pick(rng, asset.os_family, sev)
        if vuln is None:
            continue
        port = (0, "TCP", "general")
        if source == "tenable" and vuln.plugin_type == "remote":
            port = rng.choice(REMOTE_PORTS[asset.os_family])
        key = (asset.id, vuln.id if source == "tenable" else vuln.cve, port)
        if key in used:
            continue
        used.add(key)

        n_scans = len(asset.scan_days)
        backlog = asset.born_day == 0 and rng.random() < cfg.backlog_rate
        i0 = 0 if backlog else rng.randrange(n_scans)
        f = Finding(
            source=source,
            id=rng_uuid(rng),
            asset=asset,
            vuln=vuln,
            spans=[],
            port=port,
            backlog_days=rng.randint(7, 300) if backlog else 0,
        )

        force_open = False
        r = rng.random()
        if source == "tenable" and sev != "info":
            if r < cfg.accept_rate:
                f.accept_idx, force_open = -1, True  # resolved below
            elif r < cfg.accept_rate + cfg.recast_rate:
                f.recast_idx, f.recast_to = -1, rng.choice(RECAST[sev])
        elif source == "wiz":
            if r < cfg.ignored_rate:
                f.status_change, force_open = "IGNORED", True
            elif r < cfg.ignored_rate + cfg.rejected_rate:
                f.status_change, force_open = "REJECTED", True
            f.related_issues = (
                rng.randint(100, 450)
                if rng.random() < cfg.high_related_issues_rate
                else min(int(rng.expovariate(0.6)), 25)
            )

        f.spans = _draw_spans(rng, cfg, i0, n_scans, sev, interval, force_open)

        # Mutations must happen AFTER first detection, while still open.
        if f.accept_idx == -1:
            f.accept_idx = _later_open_idx(rng, f.spans, n_scans)
        if f.recast_idx == -1:
            f.recast_idx = _later_open_idx(rng, f.spans, n_scans)
            if f.recast_idx is None:
                f.recast_to = None
        if f.status_change:
            f.status_idx = _later_open_idx(rng, f.spans, n_scans)
            if f.status_idx is None:
                f.status_change = None
        findings.append(f)
    return findings
