"""Check that each service user can log in with its key and sees only what it should.

pip install "snowflake-connector-python>=3.12"
python bootstrap/snowflake/test_login.py <orgname-accountname> dev
"""

import sys
from pathlib import Path

import snowflake.connector

KEYS = Path.home() / ".snowflake-keys"


def check(account: str, env: str, svc: str) -> None:
    user = f"SVC_VULN_{svc}_{env}".upper()
    stem = KEYS / f"svc_vuln_{svc}_{env}"
    con = snowflake.connector.connect(
        account=account,
        user=user,
        authenticator="SNOWFLAKE_JWT",
        private_key_file=str(stem.with_suffix(".p8")),
        private_key_file_pwd=stem.with_suffix(".pass").read_text().strip(),
    )
    try:
        cur = con.cursor()
        role, wh, db = cur.execute("SELECT CURRENT_ROLE(), CURRENT_WAREHOUSE(), CURRENT_DATABASE()").fetchone()
        schemas = sorted(r[1] for r in cur.execute(f"SHOW SCHEMAS IN DATABASE VULN_MGMT_{env.upper()}"))
        print(f"OK  {user:26s} role={role} wh={wh} db={db} sees={schemas}")
    finally:
        con.close()


if __name__ == "__main__":
    acct, env = sys.argv[1], sys.argv[2].lower()
    for svc in ("deployer", "loader", "reporter"):
        check(acct, env, svc)
