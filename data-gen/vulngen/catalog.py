"""Synthetic vulnerability catalogs: Tenable plugins and Wiz CVE/package entries.

CVE IDs are random and synthetic (number range 90000-98999; canaries use 99xxx).
They do not refer to real advisories. Tenable plugin IDs start at 900000 so they
cannot collide with real plugin IDs.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

# (display name, package name, platform, tenable family)
PRODUCTS = [
    ("OpenSSL", "openssl", "linux", "Ubuntu Local Security Checks"),
    ("OpenSSH", "openssh-server", "linux", "Red Hat Local Security Checks"),
    ("glibc", "glibc", "linux", "Red Hat Local Security Checks"),
    ("curl", "curl", "any", "Misc."),
    ("sudo", "sudo", "linux", "Ubuntu Local Security Checks"),
    ("libxml2", "libxml2", "linux", "Ubuntu Local Security Checks"),
    ("zlib", "zlib1g", "linux", "Ubuntu Local Security Checks"),
    ("Linux Kernel", "linux-image", "linux", "Ubuntu Local Security Checks"),
    ("BIND", "bind9", "linux", "DNS"),
    ("Samba", "samba", "linux", "Misc."),
    ("Apache HTTP Server", "apache2", "linux", "Web Servers"),
    ("nginx", "nginx", "linux", "Web Servers"),
    ("Apache Tomcat", "tomcat", "any", "Web Servers"),
    ("PHP", "php", "any", "CGI abuses"),
    ("Python", "python3", "any", "Misc."),
    ("Node.js", "nodejs", "any", "Misc."),
    ("PostgreSQL", "postgresql", "any", "Databases"),
    ("MySQL", "mysql-server", "any", "Databases"),
    ("Apache Log4j", "log4j-core", "any", "Misc."),
    ("Oracle Java SE", "openjdk", "any", "Misc."),
    ("Microsoft Windows", "windows-os", "windows", "Windows : Microsoft Bulletins"),
    ("Microsoft .NET", "dotnet-runtime", "windows", "Windows : Microsoft Bulletins"),
    ("Microsoft Edge", "msedge", "windows", "Windows"),
    ("Google Chrome", "chrome", "windows", "Windows"),
    ("Mozilla Firefox", "firefox", "windows", "Windows"),
    ("7-Zip", "7zip", "windows", "Windows"),
]

INFO_PLUGINS = [
    "OS Identification",
    "Nessus Scan Information",
    "SSL Certificate Information",
    "Service Detection",
    "Traceroute Information",
    "Device Type",
    "Host Fully Qualified Domain Name",
    "Common Platform Enumeration (CPE)",
    "Software Enumeration (SSH)",
    "WMI Available",
    "SMB Signing Status",
    "TLS Version 1.2 Protocol Detection",
    "HTTP Server Type and Version",
    "Open Port Re-check",
    "Patch Report",
    "Microsoft Windows Installed Hotfixes",
]

# Realistic CVSS v3 base scores (decimal), weighted toward the common middle.
SCORE_POOL = [
    9.8,
    9.6,
    9.1,
    9.0,
    8.8,
    8.6,
    8.1,
    7.8,
    7.5,
    7.5,
    7.2,
    7.1,
    6.5,
    6.5,
    6.1,
    5.9,
    5.5,
    5.5,
    5.3,
    5.3,
    4.9,
    4.7,
    4.3,
    3.7,
    3.3,
    3.1,
    2.7,
]

DESCRIPTIONS = [
    "A buffer overflow allows a remote attacker to execute arbitrary code.",
    "Improper input validation allows a denial of service.",
    "A use-after-free allows privilege escalation by a local user.",
    "An out-of-bounds read discloses memory contents.",
    "Improper certificate validation allows a man-in-the-middle attack.",
    "A path traversal allows reading arbitrary files.",
    "An integer overflow causes a crash when parsing crafted input.",
    "Improper authentication allows bypass of access controls.",
]


def severity_from_cvss(score: float | None) -> str:
    """CVSS v3 qualitative rating, Tenable spelling (lowercase)."""
    if score is None or score == 0:
        return "info"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


@dataclass
class TenablePlugin:
    id: int
    name: str
    family: str
    platform: str
    severity: str
    cvss3_base_score: float | None
    vpr_score: float | None
    exploit_available: bool
    cves: list[str]
    package: str | None
    installed_version: str | None
    fixed_version: str | None
    publication_date: str
    plugin_type: str  # local | remote
    exploit_flip_day: int | None = None  # day index exploit_available becomes true


@dataclass
class WizVuln:
    cve: str
    package: str
    platform: str
    version: str
    fixed_version: str | None
    score: float
    severity: str  # Wiz spelling (UPPERCASE)
    has_exploit: bool
    has_kev: bool
    description: str
    rerate_day: int | None = None  # day index severity/score changes
    rerated_score: float | None = None
    exploit_flip_day: int | None = None


def _version(rng: random.Random) -> tuple[str, str]:
    major, minor, patch = rng.randint(1, 9), rng.randint(0, 20), rng.randint(0, 30)
    return f"{major}.{minor}.{patch}", f"{major}.{minor}.{patch + rng.randint(1, 5)}"


def _vpr(rng: random.Random, cvss: float) -> float:
    return round(min(10.0, max(0.1, cvss + rng.uniform(-2.5, 1.0))), 1)


class CveFactory:
    def __init__(self, rng: random.Random):
        self.rng = rng
        self._seen: set[str] = set()

    def new(self) -> str:
        while True:
            cve = f"CVE-{self.rng.randint(2022, 2026)}-{self.rng.randint(90000, 98999)}"
            if cve not in self._seen:
                self._seen.add(cve)
                return cve


def build_tenable_catalog(
    rng: random.Random, cves: CveFactory, days: int, n_plugins: int = 600, n_exploit_flips: int = 25
) -> list[TenablePlugin]:
    plugins: list[TenablePlugin] = []
    pid = 900_000
    for name in INFO_PLUGINS:
        pid += 1
        plugins.append(
            TenablePlugin(
                id=pid,
                name=name,
                family="General" if "Windows" not in name else "Windows",
                platform="windows" if ("Windows" in name or "WMI" in name or "SMB" in name) else "any",
                severity="info",
                cvss3_base_score=None,
                vpr_score=None,
                exploit_available=False,
                cves=[],
                package=None,
                installed_version=None,
                fixed_version=None,
                publication_date=f"20{rng.randint(10, 24)}-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}",
                plugin_type="remote" if rng.random() < 0.6 else "local",
            )
        )
    for _ in range(n_plugins):
        pid += 1
        display, pkg, platform, family = rng.choice(PRODUCTS)
        score = rng.choice(SCORE_POOL)
        sev = severity_from_cvss(score)
        installed, fixed = _version(rng)
        exploit = rng.random() < {"critical": 0.55, "high": 0.35, "medium": 0.15, "low": 0.05}[sev]
        plugins.append(
            TenablePlugin(
                id=pid,
                name=f"{display} < {fixed} Multiple Vulnerabilities",
                family=family,
                platform=platform,
                severity=sev,
                cvss3_base_score=score,
                vpr_score=_vpr(rng, score),
                exploit_available=exploit,
                cves=[cves.new() for _ in range(rng.randint(1, 3))],
                package=pkg,
                installed_version=installed,
                fixed_version=fixed,
                publication_date=f"20{rng.randint(22, 26)}-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}",
                plugin_type="local" if platform != "any" or rng.random() < 0.5 else "remote",
            )
        )
    # Plugin-level change: exploit_available flips false -> true mid-window (tests MERGE updates)
    candidates = [p for p in plugins if p.severity != "info" and not p.exploit_available]
    for p in rng.sample(candidates, min(n_exploit_flips, len(candidates))):
        p.exploit_flip_day = rng.randint(days // 4, (3 * days) // 4)
    return plugins


WIZ_SEV = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "NONE"}


def build_wiz_catalog(
    rng: random.Random,
    cves: CveFactory,
    days: int,
    n: int = 500,
    n_rerate: int = 25,
    n_exploit_flips: int = 25,
) -> list[WizVuln]:
    out: list[WizVuln] = []
    for _ in range(n):
        display, pkg, platform, _family = rng.choice(PRODUCTS)
        score = rng.choice(SCORE_POOL)
        sev = severity_from_cvss(score)
        installed, fixed = _version(rng)
        has_exploit = rng.random() < {"critical": 0.5, "high": 0.3, "medium": 0.12, "low": 0.04}[sev]
        out.append(
            WizVuln(
                cve=cves.new(),
                package=pkg,
                platform=platform,
                version=installed,
                fixed_version=None if rng.random() < 0.15 else fixed,  # some have no fix yet
                score=score,
                severity=WIZ_SEV[sev],
                has_exploit=has_exploit,
                has_kev=has_exploit and rng.random() < 0.3,
                description=f"{display}: {rng.choice(DESCRIPTIONS)}",
            )
        )
    # CVE-level re-rating after first detection (e.g. NVD re-scores the CVE)
    for v in rng.sample(out, min(n_rerate, len(out))):
        v.rerate_day = rng.randint(days // 4, (3 * days) // 4)
        candidates = [s for s in SCORE_POOL if severity_from_cvss(s) != severity_from_cvss(v.score)]
        v.rerated_score = rng.choice(candidates)
    flippable = [v for v in out if not v.has_exploit]
    for v in rng.sample(flippable, min(n_exploit_flips, len(flippable))):
        v.exploit_flip_day = rng.randint(days // 4, (3 * days) // 4)
    return out
