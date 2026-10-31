from conftest import small_cfg

from vulngen.generate import generate


def _hashes(manifest):
    return {s: [f["sha256"] for f in v["files"]] for s, v in manifest["sources"].items()}


def test_same_seed_is_byte_identical(dataset, tmp_path):
    again = generate(dataset["cfg"], tmp_path, log=lambda *_: None)
    assert _hashes(again) == _hashes(dataset["manifest"])
    for src in ("tenable", "wiz"):
        assert again["sources"][src]["edge_cases"] == dataset["manifest"]["sources"][src]["edge_cases"]


def test_different_seed_differs(dataset, tmp_path):
    other = generate(small_cfg(seed=7), tmp_path, log=lambda *_: None)
    assert _hashes(other) != _hashes(dataset["manifest"])


def test_canary_ids_do_not_depend_on_seed(dataset, tmp_path):
    other = generate(small_cfg(seed=7), tmp_path, log=lambda *_: None)
    ids = lambda m: {(c["label"], c["finding_id"]) for c in m["canaries"]}  # noqa: E731
    assert ids(other) == ids(dataset["manifest"])


def test_one_file_per_day_per_source(dataset):
    for src in ("tenable", "wiz"):
        files = dataset["manifest"]["sources"][src]["files"]
        assert len(files) == dataset["cfg"].days
        assert len({f["date"] for f in files}) == dataset["cfg"].days
