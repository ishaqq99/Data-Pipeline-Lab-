"""PR guardrails: keep infra out of code deploys and keep Tableau queries on the contract.

    python scripts/guardrails.py                      # scan working tree
    python scripts/guardrails.py --base origin/main   # also block edits to applied V__ migrations

A line can opt out of one rule with a trailing comment:  -- guardrail-allow: RULE_ID <reason>
Exit code 1 if any violation.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SNOWFLAKE = ROOT / "snowflake"
TABLEAU_QUERIES = ROOT / "tableau" / "queries"

IC = re.IGNORECASE
SNOWFLAKE_RULES: list[tuple[str, re.Pattern, str]] = [
    (
        "INFRA_DDL",
        re.compile(
            r"\b(CREATE|ALTER|DROP)\s+(OR\s+REPLACE\s+)?(DATABASE|SCHEMA|ROLE|USER|WAREHOUSE|"
            r"(STORAGE\s+|API\s+|NOTIFICATION\s+|SECURITY\s+)?INTEGRATION|RESOURCE\s+MONITOR|NETWORK\s+POLICY)\b",
            IC,
        ),
        "databases/schemas/roles/users/warehouses/integrations are bootstrap infra, not code",
    ),
    (
        "GRANTS",
        re.compile(r"^\s*(GRANT|REVOKE)\b", IC | re.M),
        "grants are set once in bootstrap (managed-access schemas + future grants)",
    ),
    (
        "REPLACE_TABLE",
        re.compile(r"\bCREATE\s+OR\s+REPLACE\s+(TRANSIENT\s+)?TABLE\b", IC),
        "CREATE OR REPLACE TABLE wipes data; use a V__ migration with ALTER TABLE",
    ),
    ("DROP_TABLE", re.compile(r"\bDROP\s+TABLE\b", IC), "dropping tables needs an explicit allow + reason"),
    ("TRUNCATE", re.compile(r"\bTRUNCATE\b", IC), "TRUNCATE in deploy scripts deletes data"),
    (
        "HARDCODED_DB",
        re.compile(r"\bVULN_MGMT_(DEV|PROD|PR_\w+)\b", IC),
        "never hardcode the database; scripts run unchanged in DEV, PR clones and PROD",
    ),
    (
        "DYNAMIC_SQL_CONCAT",
        re.compile(r"EXECUTE\s+IMMEDIATE[^;]*\|\|", IC | re.S),
        "EXECUTE IMMEDIATE with string concatenation (SQL injection); use bind variables",
    ),
    ("GRANT_PUBLIC", re.compile(r"\bTO\s+(ROLE\s+)?PUBLIC\b", IC), "never grant to PUBLIC"),
    (
        "EXECUTE_AS_OWNER",
        re.compile(r"\bEXECUTE\s+AS\s+OWNER\b", IC),
        "owner's-rights procedure: add '-- guardrail-allow: EXECUTE_AS_OWNER <why>' after review",
    ),
    ("SECRET", re.compile(r"(PASSWORD|SECRET|PRIVATE_KEY|TOKEN)\s*=\s*'[^']+'", IC), "hardcoded credential"),
]
TABLEAU_RULES: list[tuple[str, re.Pattern, str]] = [
    (
        "TABLEAU_SCHEMA",
        re.compile(r"\b(RAW|CURATED)_VULN_MANAGEMENT\b", IC),
        "Tableau may only query BYOD_INFOSEC (the published contract)",
    ),
    (
        "HARDCODED_DB",
        re.compile(r"\bVULN_MGMT_(DEV|PROD|PR_\w+)\b", IC),
        "use unqualified BYOD_INFOSEC.<view>; the connection picks the database",
    ),
    (
        "SELECT_STAR",
        re.compile(r"\bSELECT\s+\*", IC),
        "list columns explicitly so a new column cannot silently change the extract",
    ),
]
ALLOW = re.compile(r"--\s*guardrail-allow:\s*(\w+)", IC)


def strip_comments(sql: str) -> str:
    sql = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group().count("\n"), sql, flags=re.S)
    return re.sub(r"--[^\n]*", "", sql)


def scan(path: Path, rules) -> list[str]:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    clean = strip_comments(text)
    out = []
    for rule_id, rx, why in rules:
        for m in rx.finditer(clean):
            ln = clean.count("\n", 0, m.start()) + 1
            allowed = {a.upper() for a in ALLOW.findall(lines[ln - 1] if ln <= len(lines) else "")}
            if rule_id in allowed:
                continue
            out.append(f"{path.relative_to(ROOT)}:{ln}: [{rule_id}] {why}")
    return out


def changed_applied_migrations(base: str) -> list[str]:
    """V__ files are immutable once on main: block modify/delete/rename of existing ones."""
    diff = subprocess.run(
        ["git", "diff", "--name-status", f"{base}...HEAD", "--", "snowflake/migrations"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    bad = []
    added = []
    for row in diff.splitlines():
        status, *paths = row.split("\t")
        if not Path(paths[0]).name.startswith("V"):
            continue
        if status[0] in "MDR":
            bad.append(f"{paths[0]}: [IMMUTABLE_MIGRATION] applied V__ scripts must not change; add a new V__ file")
        elif status[0] == "A":
            added.append(paths[0])

    # schemachange skips a V__ whose version <= the highest already applied, so a branch
    # created before someone else's migration merged must bump its version.
    on_base = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", base, "--", "snowflake/migrations"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    base_versions = {v: p for p in on_base if (v := version_of(p)) is not None}
    if base_versions:
        top = max(base_versions)
        top_name = Path(base_versions[top]).name.split("__")[0]
        for p in added:
            v = version_of(p)
            if v is not None and v <= top:
                bad.append(
                    f"{p}: [STALE_VERSION] version must be newer than {top_name} "
                    "(already on base); rename with a newer timestamp"
                )
    return bad


def version_of(path: str) -> tuple[int, ...] | None:
    m = re.match(r"V([\d.]+)__", Path(path).name)
    return tuple(int(x) for x in m.group(1).strip(".").split(".")) if m else None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", help="git ref to compare against, e.g. origin/main")
    a = ap.parse_args(argv)

    problems: list[str] = []
    for p in sorted(SNOWFLAKE.rglob("*.sql")):
        problems += scan(p, SNOWFLAKE_RULES)
    for p in sorted(TABLEAU_QUERIES.rglob("*.sql")):
        problems += scan(p, TABLEAU_RULES)
    if a.base:
        problems += changed_applied_migrations(a.base)

    for p in problems:
        print(p)
    print(f"guardrails: {len(problems)} violation(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
