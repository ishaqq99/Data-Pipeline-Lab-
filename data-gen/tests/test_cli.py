from vulngen.cli import main


def test_cli_small_run(tmp_path):
    out = tmp_path / "data"
    rc = main(
        [
            "--out",
            str(out),
            "--tenable-assets",
            "10",
            "--wiz-assets",
            "10",
            "--tenable-findings",
            "50",
            "--wiz-findings",
            "50",
            "--no-gzip",
        ]
    )
    assert rc == 0
    assert (out / "manifest.json").exists()
    assert list((out / "tenable").glob("*.ndjson"))


def test_clean_refuses_non_generator_dir(tmp_path):
    victim = tmp_path / "important"
    victim.mkdir()
    (victim / "keep.txt").write_text("x")
    assert main(["--out", str(victim), "--clean"]) == 2
    assert (victim / "keep.txt").exists()


def test_rejects_too_many_tenable_assets(tmp_path):
    assert main(["--out", str(tmp_path / "d"), "--tenable-assets", "800"]) == 2
