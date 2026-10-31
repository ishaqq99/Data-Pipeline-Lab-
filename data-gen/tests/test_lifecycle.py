"""State-machine checks per finding, after removing exact duplicate / stale deliveries."""

from collections import defaultdict


def timelines(rows, id_of, seen_of):
    by_id = defaultdict(dict)
    for _file_date, r, raw in rows:
        # key on the observation time so re-delivered copies collapse into one
        by_id[id_of(r)][(seen_of(r), raw)] = r
    return {k: [v[x] for x in sorted(v)] for k, v in by_id.items()}


def test_tenable_state_machine(dataset):
    tl = timelines(
        dataset["tenable"],
        lambda r: r["finding_id"],
        lambda r: r.get("last_fixed") if r["state"] == "FIXED" else r["last_found"],
    )
    for fid, rows in tl.items():
        assert len({r["first_found"] for r in rows}) == 1, fid
        assert len({r["asset"]["uuid"] for r in rows}) == 1, fid
        prev = None
        for r in rows:
            s = r["state"]
            if prev is None:
                assert s in {"OPEN", "FIXED"}, fid
            elif prev == "FIXED":
                assert s == "REOPENED", fid  # never OPEN again after FIXED
            elif prev == "OPEN":
                assert s in {"OPEN", "FIXED"}, fid
            elif prev == "REOPENED":
                assert s in {"REOPENED", "FIXED"}, fid
            prev = s


def test_wiz_status_machine(dataset):
    tl = timelines(dataset["wiz"], lambda r: r["id"], lambda r: r["resolvedAt"] or r["lastDetectedAt"])
    for fid, rows in tl.items():
        assert len({r["firstDetectedAt"] for r in rows}) == 1, fid
        statuses = [r["status"] for r in rows]
        for a, b in zip(statuses, statuses[1:], strict=False):
            if a in {"IGNORED", "REJECTED"}:
                assert b == a, fid  # false positives / ignores are sticky


def test_mutations_happen_after_first_detection(dataset):
    tl = timelines(dataset["tenable"], lambda r: r["finding_id"], lambda r: r["last_found"])
    for fid, rows in tl.items():
        assert rows[0]["severity_modification"] == "NONE", fid
