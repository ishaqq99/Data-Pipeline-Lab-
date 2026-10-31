"""Render env.sql.tmpl into 10_env_dev.sql and 10_env_prod.sql.

python bootstrap/snowflake/render.py          # writes the two files
python bootstrap/snowflake/render.py --check  # CI: fail if rendered files are stale
"""

import sys
from pathlib import Path
from string import Template

HERE = Path(__file__).parent
EXTRA = {
    # DEV deployer may create throw-away zero-copy clones (VULN_MGMT_PR_<n>) to test PRs.
    "DEV": "USE ROLE ACCOUNTADMIN;\nGRANT CREATE DATABASE ON ACCOUNT TO ROLE VULN_DEPLOYER_DEV;\n"
    "USE ROLE SECURITYADMIN;",
    "PROD": "-- (PROD deployer gets no account-level privileges)",
}


def render() -> dict[Path, str]:
    tmpl = Template((HERE / "env.sql.tmpl").read_text())
    return {
        HERE / f"10_env_{env.lower()}.sql": tmpl.substitute(ENV=env, DEPLOYER_EXTRA=EXTRA[env])
        for env in ("DEV", "PROD")
    }


if __name__ == "__main__":
    out = render()
    if "--check" in sys.argv:
        stale = [p.name for p, s in out.items() if not p.exists() or p.read_text() != s]
        if stale:
            sys.exit(f"stale rendered files: {stale} — run python bootstrap/snowflake/render.py")
        print("rendered bootstrap files are up to date")
    else:
        for p, s in out.items():
            p.write_text(s)
            print(f"wrote {p}")
