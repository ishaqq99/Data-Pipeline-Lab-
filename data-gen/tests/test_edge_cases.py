from collections import Counter
from datetime import date, timedelta

import pytest

TENABLE_REQUIRED = [
    "reopened",
    "recasted",
    "risk_accepted",
    "severity_changed",
    "exploit_flag_changed",
    "first_found_before_window",
    "asset_stopped_scanning",
    "open_on_stale_asset",
    "asset_new_mid_window",
    "info_severity",
    "duplicate_within_file",
    "duplicate_next_day",
]
WIZ_REQUIRED = [
    "reopened",
    "ignored",
    "rejected",
    "severity_changed",
    "exploit_flag_changed",
    "related_issues_100_plus",
    "no_fixed_version",
    "first_found_before_window",
    "asset_stopped_scanning",
    "duplicate_within_file",
    "duplicate_next_day",
]


@pytest.mark.parametrize("source,required", [("tenable", TENABLE_REQUIRED), ("wiz", WIZ_REQUIRED)])
def test_every_edge_case_is_present(dataset, source, required):
    counts = dataset["manifest"]["sources"][source]["edge_case_counts"]
    missing = [t for t in required if counts.get(t, 0) == 0]
    assert not missing, missing


@pytest.mark.parametrize("source", ["tenable", "wiz"])
def test_within_file_duplicates_are_real(dataset, source):
    per_file = Counter((d, raw) for d, _, raw in dataset[source])
    assert any(n > 1 for n in per_file.values())


@pytest.mark.parametrize("source,key", [("tenable", "last_found"), ("wiz", "lastDetectedAt")])
def test_stale_next_day_redelivery_exists(dataset, source, key):
    stale = [
        r
        for d, r, _ in dataset[source]
        if r[key][:10] < d and r.get("state", r.get("status")) not in {"FIXED", "RESOLVED"}
    ]
    assert stale, "expected rows whose observation is older than the file date"


def test_related_issues_100_plus(dataset):
    assert max(r["relatedIssueCount"] for _, r, _ in dataset["wiz"]) >= 100


# ---------- canaries: exact, seed-independent expectations ----------


def canary(dataset, label):
    return next(c for c in dataset["manifest"]["canaries"] if c["label"] == label)


def day(dataset, n) -> str:
    return (date.fromisoformat(dataset["manifest"]["window"]["start"]) + timedelta(days=n)).isoformat()


def test_canary_fixed(dataset):
    c = canary(dataset, "TN-C2")["final_row"]
    assert c["state"] == "FIXED"
    assert c["last_fixed"][:10] == day(dataset, 45) and c["last_found"][:10] == day(dataset, 44)


def test_canary_reopened(dataset):
    c = canary(dataset, "TN-C3")["final_row"]
    assert c["state"] == "REOPENED" and c["last_fixed"][:10] == day(dataset, 33)


def test_canary_recast_and_accepted(dataset):
    assert canary(dataset, "TN-C4")["final_row"]["severity"] == "medium"
    assert canary(dataset, "TN-C4")["final_row"]["severity_modification"] == "RECASTED"
    assert canary(dataset, "TN-C5")["final_row"]["severity_modification"] == "ACCEPTED"


def test_canary_stale_asset_and_backlog(dataset):
    assert canary(dataset, "TN-C8")["final_row"]["last_found"][:10] == day(dataset, 119)
    assert canary(dataset, "TN-C9")["first_found"][:10] == day(dataset, -90)


def test_canary_wiz(dataset):
    assert canary(dataset, "WZ-C3")["final_row"]["status"] == "IGNORED"
    assert canary(dataset, "WZ-C4")["final_row"]["status"] == "REJECTED"
    c5 = canary(dataset, "WZ-C5")["final_row"]
    assert (c5["severity"], c5["score"]) == ("CRITICAL", 9.1)
    assert canary(dataset, "WZ-C6")["final_row"]["relatedIssueCount"] == 250


def test_canary_duplicate_delivery(dataset):
    fid = canary(dataset, "WZ-C7")["finding_id"]
    d60, d61 = day(dataset, 60), day(dataset, 61)
    in_60 = [r for d, r, _ in dataset["wiz"] if d == d60 and r["id"] == fid]
    in_61 = [r for d, r, _ in dataset["wiz"] if d == d61 and r["id"] == fid]
    assert len(in_60) == 2  # duplicated within the file
    assert sorted(r["lastDetectedAt"][:10] for r in in_61) == [d60, d61]  # stale copy + fresh row
