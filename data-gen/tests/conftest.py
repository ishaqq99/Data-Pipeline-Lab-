import gzip
import json
from dataclasses import replace
from pathlib import Path

import pytest

from vulngen.config import GenConfig
from vulngen.generate import generate

# Full 183-day window (so canaries fit) but a small population, so tests run in seconds.
SMALL = GenConfig(tenable_assets=60, wiz_assets=80, tenable_findings=1500, wiz_findings=1500)


def small_cfg(**overrides) -> GenConfig:
    return replace(SMALL, **overrides)


def read_lines(path: Path) -> list[bytes]:
    raw = path.read_bytes()
    if path.suffix == ".gz":
        raw = gzip.decompress(raw)
    return [ln for ln in raw.split(b"\n") if ln]


def load(out: Path, manifest: dict, source: str) -> list[tuple[str, dict, bytes]]:
    """All delivered rows as (file_date, record, raw_line), in file order."""
    rows = []
    for f in manifest["sources"][source]["files"]:
        for ln in read_lines(out / f["file"]):
            rows.append((f["date"], json.loads(ln), ln))
    return rows


@pytest.fixture(scope="session")
def dataset(tmp_path_factory):
    out = tmp_path_factory.mktemp("data")
    manifest = generate(SMALL, out, log=lambda *_: None)
    return {
        "out": out,
        "cfg": SMALL,
        "manifest": manifest,
        "tenable": load(out, manifest, "tenable"),
        "wiz": load(out, manifest, "wiz"),
    }
