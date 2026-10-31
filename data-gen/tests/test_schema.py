import ipaddress
import re
from datetime import datetime, timedelta

TN_SEV = {"info", "low", "medium", "high", "critical"}
TN_STATE = {"OPEN", "REOPENED", "FIXED"}
TN_MOD = {"NONE", "RECASTED", "ACCEPTED"}
WZ_SEV = {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
WZ_STATUS = {"OPEN", "RESOLVED", "IGNORED", "REJECTED"}
RFC5737 = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def one_decimal(x) -> bool:
    return isinstance(x, (int, float)) and 0 <= x <= 10 and round(x, 1) == x


def window(dataset):
    start = datetime.fromisoformat(dataset["manifest"]["window"]["start"] + "T00:00:00+00:00")
    return start, start + timedelta(days=dataset["cfg"].days)


def test_tenable_rows(dataset):
    start, end = window(dataset)
    for file_date, r, _ in dataset["tenable"]:
        assert r["severity"] in TN_SEV and r["state"] in TN_STATE
        assert r["severity_modification"] in TN_MOD
        assert r["severity_id"] == ["info", "low", "medium", "high", "critical"].index(r["severity"])
        assert r["finding_id"] and r["asset"]["uuid"]
        assert r["asset"]["fqdn"].endswith(".example.com")
        assert any(ipaddress.ip_address(r["asset"]["ipv4"]) in n for n in RFC5737)
        p = r["plugin"]
        if "cvss3_base_score" in p:
            assert one_decimal(p["cvss3_base_score"])
        else:
            assert r["severity_default_id"] == 0  # only info plugins lack CVSS
        if "vpr" in p:
            assert one_decimal(p["vpr"]["score"])
        ff, lf = ts(r["first_found"]), ts(r["last_found"])
        assert ff <= lf and start <= lf < end
        if r["state"] == "OPEN":
            assert "last_fixed" not in r
        else:  # FIXED and REOPENED carry last_fixed
            assert start <= ts(r["last_fixed"]) < end
        if r["state"] == "FIXED":
            assert ts(r["last_fixed"]) > lf
            assert r["last_fixed"][:10] <= file_date  # == except stale re-deliveries
        else:
            assert r["last_found"][:10] <= file_date  # <= because of stale re-deliveries


def test_wiz_rows(dataset):
    start, end = window(dataset)
    for _file_date, r, _ in dataset["wiz"]:
        assert r["severity"] in WZ_SEV and r["status"] in WZ_STATUS
        assert r["severity"] == r["CVSSSeverity"]
        assert re.fullmatch(r"CVE-\d{4}-\d{5}", r["name"])
        assert one_decimal(r["score"])
        assert isinstance(r["relatedIssueCount"], int) and r["relatedIssueCount"] >= 0
        assert r["vulnerableAsset"]["type"] in {"VIRTUAL_MACHINE", "CONTAINER_IMAGE", "SERVERLESS"}
        assert r["vulnerableAsset"]["cloudPlatform"] in {"Azure", "AWS", "GCP"}
        fd, ld = ts(r["firstDetectedAt"]), ts(r["lastDetectedAt"])
        assert fd <= ld and start <= ld < end
        if r["status"] == "RESOLVED":
            assert ts(r["resolvedAt"]) > ld
        else:
            assert r["resolvedAt"] is None


def test_decimal_cvss_present(dataset):
    scores = {r["score"] for _, r, _ in dataset["wiz"]}
    assert 7.5 in scores and any(s != int(s) for s in scores)


def test_no_real_infrastructure_identifiers(dataset):
    """Every IPv4 must be RFC 5737; every domain must be under example.com."""
    ip_re = re.compile(rb"\b\d{1,3}(?:\.\d{1,3}){3}\b")
    dom_re = re.compile(rb"\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|io|local|corp)\b")
    for src in ("tenable", "wiz"):
        for _, _, raw in dataset[src]:
            for ip in ip_re.findall(raw):
                assert any(ipaddress.ip_address(ip.decode()) in n for n in RFC5737), ip
            for dom in dom_re.findall(raw):
                assert dom == b"example.com" or dom.endswith(b".example.com"), dom
