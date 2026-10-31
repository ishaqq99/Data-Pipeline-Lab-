"""Synthetic assets and their scan schedules.

Tenable assets: on-prem style hosts, *.lab.example.com, IPv4 from RFC 5737 only.
Wiz assets: cloud VMs, container images and serverless functions.
"""

from __future__ import annotations

import ipaddress
import random
import uuid
from dataclasses import dataclass, field

RFC5737_NETS = ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"]
DOMAIN = "lab.example.com"


def rfc5737_hosts() -> list[str]:
    hosts: list[str] = []
    for net in RFC5737_NETS:
        hosts.extend(str(h) for h in ipaddress.ip_network(net).hosts())
    return hosts  # 762 addresses


def rng_uuid(rng: random.Random) -> str:
    return str(uuid.UUID(int=rng.getrandbits(128), version=4))


TENABLE_ROLES = [  # (prefix, os_family, os choices, weight)
    ("srv-web", "linux", ["Linux Kernel 5.15 on Ubuntu 22.04", "Linux Kernel 6.8 on Ubuntu 24.04"], 3),
    ("srv-app", "linux", ["Red Hat Enterprise Linux 8", "Red Hat Enterprise Linux 9"], 3),
    ("srv-db", "linux", ["Red Hat Enterprise Linux 9", "Linux Kernel 6.8 on Ubuntu 24.04"], 2),
    ("srv-win", "windows", ["Microsoft Windows Server 2019", "Microsoft Windows Server 2022"], 3),
    ("dc", "windows", ["Microsoft Windows Server 2022"], 1),
    ("fs", "windows", ["Microsoft Windows Server 2019"], 1),
    ("ws", "windows", ["Microsoft Windows 11 Enterprise", "Microsoft Windows 10 Enterprise"], 6),
]

WIZ_ROLES = ["web", "api", "worker", "batch", "auth", "search", "cache", "etl", "report", "gateway"]
CLOUDS = [
    ("Azure", 0.6, ["eastus", "westus2", "centralus"]),
    ("AWS", 0.3, ["us-east-1", "us-west-2"]),
    ("GCP", 0.1, ["us-central1", "us-west1"]),
]


@dataclass
class Asset:
    source: str  # tenable | wiz
    id: str
    name: str
    os_family: str  # linux | windows
    attrs: dict
    born_day: int = 0
    dark_day: int | None = None  # first day it is NOT scanned any more
    scan_days: list[int] = field(default_factory=list)
    scan_minute: int = 0  # minutes after midnight UTC the scan runs
    weight: float = 1.0  # relative number of findings
    is_canary: bool = False


def _lifecycle(rng: random.Random, days: int, interval: int, new_rate: float, stale_rate: float):
    born = rng.randint(1, int(days * 0.6)) if rng.random() < new_rate else 0
    dark = None
    if rng.random() < stale_rate:
        lo = max(born + 3 * interval, int(days * 0.3))
        hi = int(days * 0.8)
        if lo < hi:
            dark = rng.randint(lo, hi)
    return born, dark


def scan_schedule(
    rng: random.Random, born: int, dark: int | None, days: int, interval: int, missed_rate: float
) -> list[int]:
    offset = rng.randrange(interval)
    end = dark if dark is not None else days
    d = born + ((offset - born) % interval)
    out: list[int] = []
    while d < end:
        if rng.random() >= missed_rate:
            out.append(d)
        d += interval
    return out or [born]


def build_tenable_assets(rng: random.Random, cfg, ips: list[str]) -> list[Asset]:
    roles = [r for r in TENABLE_ROLES for _ in range(r[3])]
    counters: dict[str, int] = {}
    assets: list[Asset] = []
    for i in range(cfg.tenable_assets):
        prefix, fam, oses, _w = rng.choice(roles)
        counters[prefix] = counters.get(prefix, 0) + 1
        hostname = f"{prefix}-{counters[prefix]:04d}"
        born, dark = _lifecycle(
            rng, cfg.days, cfg.tenable_scan_interval, cfg.new_asset_rate, cfg.stale_asset_rate
        )
        a = Asset(
            source="tenable",
            id=rng_uuid(rng),
            name=hostname,
            os_family=fam,
            attrs={
                "hostname": hostname,
                "fqdn": f"{hostname}.{DOMAIN}",
                "ipv4": ips[i],
                "operating_system": [rng.choice(oses)],
                "device_type": "general-purpose",
            },
            born_day=born,
            dark_day=dark,
            scan_minute=rng.randint(60, 300),
            weight=rng.paretovariate(2.0),
        )
        a.scan_days = scan_schedule(
            rng, born, dark, cfg.days, cfg.tenable_scan_interval, cfg.missed_scan_rate
        )
        assets.append(a)
    return assets


def build_wiz_assets(rng: random.Random, cfg) -> list[Asset]:
    subs = {}
    for cloud, _p, _r in CLOUDS:
        subs[cloud] = [
            {"subscriptionName": f"sub-lab-{env}-{n:02d}", "subscriptionExternalId": rng_uuid(rng)}
            for env in ("prod", "nonprod")
            for n in (1, 2)
        ]
    assets: list[Asset] = []
    counters: dict[str, int] = {}
    for _ in range(cfg.wiz_assets):
        r = rng.random()
        cloud, regions = (
            ("Azure", CLOUDS[0][2])
            if r < 0.6
            else (("AWS", CLOUDS[1][2]) if r < 0.9 else ("GCP", CLOUDS[2][2]))
        )
        t = rng.random()
        atype = "VIRTUAL_MACHINE" if t < 0.5 else ("CONTAINER_IMAGE" if t < 0.85 else "SERVERLESS")
        role = rng.choice(WIZ_ROLES)
        key = f"{atype}-{role}"
        counters[key] = counters.get(key, 0) + 1
        n = counters[key]
        if atype == "VIRTUAL_MACHINE":
            win = rng.random() < 0.2
            name = f"vm-{role}-{n:04d}"
            os_name = (
                "Windows Server 2022"
                if win
                else rng.choice(["Ubuntu 22.04", "Ubuntu 24.04", "Azure Linux 3.0", "Amazon Linux 2023"])
            )
            fam = "windows" if win else "linux"
        elif atype == "CONTAINER_IMAGE":
            name = f"registry.example.com/lab/{role}-svc:1.{n % 20}.{n}"
            os_name, fam = rng.choice(["Debian 12", "Alpine 3.20", "Ubuntu 24.04"]), "linux"
        else:
            name = f"fn-{role}-{n:04d}"
            os_name, fam = None, "linux"
        born, dark = _lifecycle(
            rng, cfg.days, cfg.wiz_scan_interval, cfg.new_asset_rate, cfg.stale_asset_rate
        )
        sub = rng.choice(subs[cloud])
        a = Asset(
            source="wiz",
            id=rng_uuid(rng),
            name=name,
            os_family=fam,
            attrs={
                "type": atype,
                "name": name,
                "cloudPlatform": cloud,
                "subscriptionName": sub["subscriptionName"],
                "subscriptionExternalId": sub["subscriptionExternalId"],
                "region": rng.choice(regions),
                "operatingSystem": os_name,
            },
            born_day=born,
            dark_day=dark,
            scan_minute=rng.randint(0, 1380),
            weight=rng.paretovariate(2.0),
        )
        a.scan_days = scan_schedule(rng, born, dark, cfg.days, cfg.wiz_scan_interval, cfg.missed_scan_rate)
        assets.append(a)
    return assets
