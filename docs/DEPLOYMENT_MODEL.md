# Deployment model: Git drives code; infra is set once

## The split

| Layer | Examples | Created by | Changed by a PR merge? |
|---|---|---|---|
| **Infra** | Azure RG, storage, Key Vault, ADF instances; Snowflake database, the 4 schemas, roles, users, warehouse, storage integration, grants; Tableau site and projects | You, once, from `bootstrap/` (`docs/SETUP.md`) | **Never.** The pipeline's identities lack the privileges, and `scripts/guardrails.py` fails the PR if `snowflake/` contains such statements. |
| **Code** | Tables (shape only), views, procedures, file formats, stages, tasks; ADF pipelines, datasets, linked services, triggers; Tableau `.tds` / `.twb` / custom SQL | A PR | Yes — and **only what changed** is deployed. |

## Only what changed gets deployed

| Tool | Mechanism | What happens on a merge that touches one view |
|---|---|---|
| **Snowflake** | [schemachange](https://pypi.org/project/schemachange/) keeps a history table (`SCHEMACHANGE.CHANGE_HISTORY`). `V__` scripts run **once** ever; `R__` scripts rerun **only when their content (checksum) changes**. | Only that view's `R__` script runs. Nothing else is touched; table data is untouched. |
| **ADF** | CD job runs only if `adf/**` changed. The ARM template deploys in *Incremental* mode, and the generated pre/post script stops/starts **only the triggers that changed**. | ADF job is skipped entirely. |
| **Tableau** | Publish script uses `git diff` between the previous and new `main` and republishes **only changed** `.tds`/`.twb` files. | Tableau job is skipped entirely. |
| **Infra** | `bootstrap/` is never referenced by any CD workflow. | — |

Job routing in `cd.yml` (Phase 4) uses a path filter, so a Snowflake-only PR never runs the ADF or Tableau jobs.

## Snowflake folder layout and naming

```
snowflake/
  migrations/                         V__  run once, in version order — table shape changes
    raw_vuln_management/      V2026.11.02.0900__create_tenable_raw.sql
    curated_vuln_management/  V2026.11.03.1400__create_finding.sql
                              V2026.11.20.1015__finding_add_epss.sql     ← ALTER TABLE ... ADD COLUMN
    byod_infosec/             V2026.11.05.1100__create_monthly_snapshot.sql (only if a table is needed)
  objects/                            R__  rerun when changed — views, procedures, functions
    curated_vuln_management/  R__10_curated_sp_merge_tenable.sql
    byod_infosec/             R__20_byod_vw_open_findings.sql
  contracts/byod_infosec.yml          the published column contract (Phase 3)
  tests/                              data tests run after every deploy
```

Rules (enforced by `scripts/guardrails.py` on every PR):

1. **Never name the database.** Scripts say `CURATED_VULN_MANAGEMENT.FINDING`, not `VULN_MGMT_PROD....`; the
   connection decides the database, so the same script runs in a PR clone, DEV and PROD.
2. **Tables only via `V__`, and never `CREATE OR REPLACE TABLE`.** Change a table with a new `V__` file
   (`ALTER TABLE ... ADD COLUMN`). Applied `V__` files are **immutable** — editing one fails the PR.
3. **Views/procedures via `R__` with `CREATE OR REPLACE ... COPY GRANTS`.** They hold no data, so replacing is safe.
4. **No infra DDL, no `GRANT`/`REVOKE`.** Access comes from future grants set in bootstrap.
5. **Version = timestamp** (`VYYYY.MM.DD.HHMM__`). If your branch's version is older than one already on `main`,
   schemachange would skip it — the PR check catches that; rename the file to a newer timestamp.
6. `R__` order is alphabetical, so prefix: `10_` curated objects, `20_` BYOD views (BYOD depends on curated).

## Not breaking Tableau (the BYOD_INFOSEC contract)

Tableau only ever reads `BYOD_INFOSEC`. Treat it like a public API:

| Change | Allowed? | How |
|---|---|---|
| Add a column to a BYOD view | ✅ | Edit the `R__` view, add the column to `contracts/byod_infosec.yml` |
| Change logic without changing columns | ✅ | Edit the `R__` view/procedure |
| Rename / drop / retype a BYOD column | ❌ in one step | **Expand → migrate → contract:** (1) add the new column alongside the old; (2) move Tableau queries to it; (3) a later PR removes the old column once no file in `tableau/` references it |
| Breaking redesign of a view | ✅ | New view `VW_X_V2`, migrate Tableau, retire `VW_X` later |
| Tableau custom SQL against RAW/CURATED, `SELECT *`, hardcoded DB | ❌ | Guardrail fails the PR |

Every PR is proven against real Snowflake before merge (Phase 4):

```
PR opened
  → CREATE DATABASE VULN_MGMT_PR_<n> CLONE VULN_MGMT_DEV     (zero-copy: seconds, ~no storage cost)
  → schemachange deploy into the clone                       (only this PR's new/changed scripts run)
  → contract check: BYOD columns/types in the clone vs contracts/byod_infosec.yml
                    (removed/retyped column = fail; added column must be in the contract)
  → compile every tableau/queries/*.sql with EXPLAIN in the clone  (missing column/view = fail)
  → data tests (row counts, no duplicates, SLA math on the canaries)
  → DROP DATABASE VULN_MGMT_PR_<n>
merge → deploy DEV → tests → [you approve] → deploy PROD → tests
```

So a broken column fails **in the PR**, never in DEV, PROD or a dashboard.

## A normal day

```bash
git switch -c feat/exploitable-criticals
# edit snowflake/objects/byod_infosec/R__20_byod_vw_open_findings.sql   (add IS_EXPLOITABLE)
# edit snowflake/contracts/byod_infosec.yml                              (declare the new column)
# edit tableau/queries/open_findings.sql                                 (select it)
git commit -am "Add IS_EXPLOITABLE to open findings" && git push -u origin HEAD
gh pr create --fill
```
CI runs on the PR. Merge → only that view is redeployed to DEV, then PROD after approval, and only the
changed Tableau data source is republished. Nothing else is rebuilt.
