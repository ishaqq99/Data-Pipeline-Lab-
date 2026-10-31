"""pytest scripts/test_guardrails.py"""

import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("guardrails", Path(__file__).with_name("guardrails.py"))
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)


def run(tmp_path, monkeypatch, rel, sql):
    monkeypatch.setattr(g, "ROOT", tmp_path)
    monkeypatch.setattr(g, "SNOWFLAKE", tmp_path / "snowflake")
    monkeypatch.setattr(g, "TABLEAU_QUERIES", tmp_path / "tableau" / "queries")
    f = tmp_path / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(sql)
    rules = g.TABLEAU_RULES if "tableau" in rel else g.SNOWFLAKE_RULES
    return [p.split("[")[1].split("]")[0] for p in g.scan(f, rules)]


M = "snowflake/migrations/curated_vuln_management/V2026.10.30.1__x.sql"


def test_blocks_infra_and_grants(tmp_path, monkeypatch):
    sql = "CREATE SCHEMA FOO;\nGRANT SELECT ON TABLE T TO ROLE R;\nDROP WAREHOUSE W;"
    assert run(tmp_path, monkeypatch, M, sql) == ["INFRA_DDL", "INFRA_DDL", "GRANTS"]


def test_blocks_replace_table_and_hardcoded_db(tmp_path, monkeypatch):
    sql = "CREATE OR REPLACE TABLE VULN_MGMT_PROD.CURATED_VULN_MANAGEMENT.T (a INT);"
    assert sorted(run(tmp_path, monkeypatch, M, sql)) == ["HARDCODED_DB", "REPLACE_TABLE"]


def test_allows_normal_code(tmp_path, monkeypatch):
    sql = (
        "CREATE TABLE IF NOT EXISTS CURATED_VULN_MANAGEMENT.T (a NUMBER(10,0));\n"
        "ALTER TABLE CURATED_VULN_MANAGEMENT.T ADD COLUMN b TIMESTAMP_TZ;\n"
        "-- DROP SCHEMA in a comment is fine\n"
        "CREATE OR REPLACE VIEW BYOD_INFOSEC.V COPY GRANTS AS SELECT a FROM CURATED_VULN_MANAGEMENT.T;"
    )
    assert run(tmp_path, monkeypatch, M, sql) == []


def test_allow_annotation(tmp_path, monkeypatch):
    sql = (
        "CREATE PROCEDURE P() RETURNS INT LANGUAGE SQL "
        "EXECUTE AS OWNER -- guardrail-allow: EXECUTE_AS_OWNER merge\n"
        "AS $$ BEGIN RETURN 1; END $$;"
    )
    assert run(tmp_path, monkeypatch, M, sql) == []


def test_dynamic_sql_concat(tmp_path, monkeypatch):
    sql = "EXECUTE IMMEDIATE 'SELECT * FROM ' || :tbl;"
    assert run(tmp_path, monkeypatch, M, sql) == ["DYNAMIC_SQL_CONCAT"]


def test_tableau_queries_only_hit_contract(tmp_path, monkeypatch):
    rel = "tableau/queries/open_findings.sql"
    assert run(tmp_path, monkeypatch, rel, "SELECT * FROM CURATED_VULN_MANAGEMENT.FINDING") == [
        "TABLEAU_SCHEMA",
        "SELECT_STAR",
    ]
    assert run(tmp_path, monkeypatch, rel, "SELECT source, severity FROM BYOD_INFOSEC.VW_FINDINGS") == []
