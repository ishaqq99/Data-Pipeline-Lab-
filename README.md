# Data-Pipeline-Lab — CI/CD for Tenable/Wiz data: GitHub → ADF → Snowflake → Tableau

Personal practice lab. **Synthetic data only**: hostnames are `*.lab.example.com`, IPv4 addresses come from
RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), CVE IDs and Tenable plugin IDs are random and
do not refer to real advisories.

- **One-time manual setup** (Azure, Snowflake, Tableau): [`docs/SETUP.md`](docs/SETUP.md)
- **How code changes are deployed** (and why infra never is): [`docs/DEPLOYMENT_MODEL.md`](docs/DEPLOYMENT_MODEL.md)

```
bootstrap/                 ONE-TIME infra, run by hand — never by the pipeline
  azure/                   oidc.sh (GitHub→Azure login), main.bicep (storage, Key Vault, ADF)
  snowflake/               account + per-env SQL (DB, schemas, roles, users, grants), keys.sh
data-gen/                  synthetic Tenable/Wiz generator + tests
adf/                       ADF Git root folder (dev factory commits here)
snowflake/
  migrations/<schema>/     V__ scripts: run once (tables)
  objects/<schema>/        R__ scripts: rerun when changed (views, procedures)
  contracts/               BYOD_INFOSEC column contract
  tests/                   data tests
tableau/
  datasources/ workbooks/  .tds / .twb only
  queries/                 custom SQL used by Tableau — may only read BYOD_INFOSEC
scripts/guardrails.py      PR check: no infra DDL/grants, immutable migrations, Tableau → BYOD only
.github/workflows/         ci-python.yml, ci-guardrails.yml (CD added in later phases)
data/                      generated output — gitignored
```

Snowflake layout (per environment `VULN_MGMT_DEV` / `VULN_MGMT_PROD`):
`RAW_VULN_MANAGEMENT` (tool payloads) → procedures → `CURATED_VULN_MANAGEMENT` (typed tables) →
views → `BYOD_INFOSEC` (published contract, read by Tableau).

## Phase 1 quickstart

```bash
cd data-gen
python3.12 -m venv .venv
source .venv/bin/activate            # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -e ".[dev]"
pytest                               # 27 tests, ~15 s
ruff check . && ruff format --check .
python -m vulngen --out ../data --clean     # ~10 s, ~35 MB gzipped
```

## What gets generated

| | Tenable (`vulns/export` shape) | Wiz (`vulnerabilityFindings` node shape) |
|---|---|---|
| Assets | 752 (750 + 2 canary) | 1,251 (1,250 + 1 canary) |
| Findings | 11,010 | 9,008 |
| Rows delivered (6 months) | ~104 k | ~183 k |
| Files | `data/tenable/tenable_vulns_YYYY-MM-DD.ndjson.gz` × 183 | `data/wiz/wiz_vulnerability_findings_YYYY-MM-DD.ndjson.gz` × 183 |
| Scan cadence | weekly per asset | every 3 days per asset |

Window: 2026-04-01 → 2026-09-30. Seed 42. Same seed ⇒ byte-identical files (tested).

**Delivery model:** a finding appears in a day's file only when its asset was scanned that day (incremental export,
like `since=` / `updatedAt` filtering). So the *latest* row per finding is its current state, and an asset that stops
being scanned leaves its findings frozen as OPEN with a stale `last_found` — exactly what a real export does.

Format is NDJSON (one object per line) → Snowflake `FILE_FORMAT = (TYPE = JSON)`, no `STRIP_OUTER_ARRAY`.

Deliberate source differences to handle in the curated model:
- Severity spelling: Tenable `info/low/medium/high/critical`, Wiz `NONE/LOW/MEDIUM/HIGH/CRITICAL`.
- Timestamps: Tenable `2026-05-01T03:58:00.000Z`, Wiz `2026-05-01T03:58:00Z`.
- Missing values: Tenable omits the key (e.g. no `cvss3_base_score` on info plugins), Wiz sends `null`.
- Natural keys: Tenable `finding_id` (also unique on asset.uuid + plugin.id + port + protocol); Wiz `id`.

## Edge cases (all tagged in `data/manifest.json → sources.<src>.edge_cases`)

| Tag | Tenable | Wiz | What it tests downstream |
|---|---|---|---|
| `reopened` | `state=REOPENED`, `last_fixed` kept | `RESOLVED` → `OPEN` again | is_active, MTTR, SLA restart rules |
| `recasted` / `severity_changed` | `severity_modification=RECASTED`, `severity` ≠ `severity_default_id` | CVE re-rated (score + severity) | MERGE updates severity |
| `risk_accepted` | `severity_modification=ACCEPTED` | — | is_risk_accepted |
| `ignored` / `rejected` | — | `status=IGNORED` / `REJECTED` | is_false_positive, shown separately |
| `exploit_flag_changed` | `exploit_available` false → true | `hasExploit` false → true | MERGE updates exploit flag |
| `first_found_before_window` | `first_found` up to 300 days before window | same for `firstDetectedAt` | already-breaching on first load |
| `asset_stopped_scanning` / `open_on_stale_asset` | asset goes dark mid-window | same | freshness / stale-asset reporting |
| `asset_new_mid_window` | asset first scanned mid-window | same | |
| `info_severity` | no CVSS, no SLA | — | Low/Info = no SLA |
| `related_issues_100_plus` | — | `relatedIssueCount` 100–450 | NUMBER(10,0), outliers |
| `no_fixed_version` | — | `fixedVersion: null` | nullable columns |
| `duplicate_within_file` | identical line twice in one file | same | dedupe before MERGE |
| `duplicate_next_day` | stale copy re-sent in next day's file | same | MERGE must not overwrite newer state with older |
| decimal CVSS | 7.5, 9.8, 5.3 … | same | NUMBER(4,1), not INT |

## Canaries (fixed IDs, identical for every seed — use for exact SLA tests in Phase 3)

Day N = window start + N days (day 0 = 2026-04-01). Canary assets are scanned daily. Full expectations,
including `finding_id`, are written to `manifest.json → canaries`.

| Label | Setup |
|---|---|
| TN-C1 | critical, found day 5, never fixed, exploit available |
| TN-C2 | high, found day 10, FIXED day 45 (`last_found` day 44) |
| TN-C3 | medium, found day 12, fixed day 33, REOPENED day 60, open at end |
| TN-C4 | high found day 15, RECASTED → medium from day 31 |
| TN-C5 | critical found day 20, ACCEPTED from day 40 |
| TN-C6 | low, open (no SLA) |
| TN-C7 | info, open (no SLA) |
| TN-C8 | high on `canary-tn-02`, which stops being scanned after day 119 |
| TN-C9 | critical, `first_found` 90 days before window, FIXED day 70 |
| TN-C10 | medium found day 50, `exploit_available` → true on day 80 |
| WZ-C1 | CRITICAL 9.8, hasExploit, open from day 5 |
| WZ-C2 | HIGH 7.5, found day 10, RESOLVED day 40 |
| WZ-C3 | MEDIUM, IGNORED from day 30 |
| WZ-C4 | HIGH, REJECTED (false positive) from day 20 |
| WZ-C5 | MEDIUM 6.5 → re-rated CRITICAL 9.1 on day 50 |
| WZ-C6 | HIGH, 250 related issues |
| WZ-C7 | HIGH 7.5; day-60 row duplicated in its file **and** re-sent (stale) in the day-61 file |
| WZ-C8 | LOW, no fixed version |

## Generator options

```bash
python -m vulngen --help
python -m vulngen --out ../data --seed 7                 # different dataset
python -m vulngen --out ../data --start 2026-07-01       # different window (canaries move with it)
python -m vulngen --out ../data --no-gzip                # plain .ndjson for eyeballing
```
