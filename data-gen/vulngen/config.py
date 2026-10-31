"""Generator configuration. Every knob that changes output lives here."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import date

SEVERITIES = ("info", "low", "medium", "high", "critical")  # Tenable spelling, ordered


@dataclass(frozen=True)
class GenConfig:
    seed: int = 42
    start: date = date(2026, 4, 1)
    days: int = 183  # 2026-04-01 .. 2026-09-30

    # Population
    tenable_assets: int = 750  # RFC 5737 has 762 usable host addresses
    wiz_assets: int = 1250
    tenable_findings: int = 11_000
    wiz_findings: int = 9_000

    # Scan cadence (days). Each asset gets a fixed offset inside the interval.
    tenable_scan_interval: int = 7
    wiz_scan_interval: int = 3
    missed_scan_rate: float = 0.05

    # Asset lifecycle edge cases
    new_asset_rate: float = 0.08  # first scanned partway through the window
    stale_asset_rate: float = 0.05  # stop being scanned partway through

    # Finding lifecycle
    backlog_rate: float = 0.30  # first_found before the window starts
    never_fixed_rate: float = 0.25
    reopen_rate: float = 0.06
    mean_days_to_fix: dict = field(
        default_factory=lambda: {
            "critical": 20,
            "high": 35,
            "medium": 60,
            "low": 90,
            "info": 150,
        }
    )

    # Tenable-specific
    recast_rate: float = 0.03  # severity_modification = RECASTED
    accept_rate: float = 0.02  # severity_modification = ACCEPTED (risk accepted)
    tenable_exploit_flip_plugins: int = 25  # plugins whose exploit_available turns true mid-window

    # Wiz-specific
    ignored_rate: float = 0.04
    rejected_rate: float = 0.02
    wiz_rerate_cves: int = 25  # CVEs whose severity/score is re-rated mid-window
    wiz_exploit_flip_cves: int = 25
    high_related_issues_rate: float = 0.01  # 100+ related issues

    # Delivery quirks
    dup_within_file_rate: float = 0.005
    dup_next_day_rate: float = 0.01

    # Output
    gzip: bool = True
    include_canaries: bool = True

    def to_dict(self) -> dict:
        d = asdict(self)
        d["start"] = self.start.isoformat()
        return d

    def validate(self) -> None:
        if self.tenable_assets > 762 - 2:  # 2 addresses reserved for canary assets
            raise ValueError("tenable_assets must be <= 760 (RFC 5737 address space)")
        if self.include_canaries and self.days < 130:
            raise ValueError("canaries need days >= 130 (or pass --no-canaries)")
        if min(self.tenable_scan_interval, self.wiz_scan_interval) < 1:
            raise ValueError("scan intervals must be >= 1")
