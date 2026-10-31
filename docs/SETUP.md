# One-time manual setup

Everything in this file is **infrastructure**: you do it once, by hand, from the files in
`bootstrap/`. After this, every change reaches Azure, Snowflake and Tableau only through a
pull request (see `docs/DEPLOYMENT_MODEL.md`). The pipeline itself has no permission to redo
or change anything created here.

Do the steps in order. Each ends with **✅ Check** — don't continue until it passes.

| Part | Time | Cost |
|---|---|---|
| 0. Tools | 10 min | free |
| 1. GitHub settings | 10 min | free (public repo) |
| 2. Azure: storage, Key Vault, ADF dev + prod | 30 min | Azure free credit; idle ADF costs ~$0 |
| 3. Snowflake: database, 3 schemas, roles, users, keys | 30 min | 30-day trial; capped by a resource monitor |
| 4. Connect Snowflake ⇄ Azure, put keys in Key Vault + GitHub | 20 min | free |
| 5. Tableau Cloud (**later — start at the Tableau phase**, the trial is only 14 days) | 20 min | 14-day trial |

---

## 0. Tools on your machine

- Git, Python 3.12, [Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli) (`az bicep install` once), OpenSSL 3
  (macOS/Linux have it; on Windows use **Git Bash**, which includes it), optional [GitHub CLI](https://cli.github.com/) `gh`.
- Pick a **suffix** for globally unique names: 3–8 lowercase letters/digits, e.g. `iq7k2`. Used below as `$SUFFIX`.

```bash
export SUFFIX=iq7k2          # change me
export REPO=ishaqq99/Data-Pipeline-Lab-
export LOCATION=westus2
```

---

## 1. GitHub repository settings

Repo → **Settings**:

1. **General → Pull Requests**: allow *Squash merging* only; tick *Automatically delete head branches*.
2. **Rules → Rulesets → New branch ruleset** `protect-main`, Enforcement *Active*, target *Default branch*:
   - Restrict deletions; Block force pushes; Require linear history
   - Require a pull request before merging — **required approvals: 0** (you can't approve your own PR)
   - Require status checks to pass: add `test` and `guardrails` *after* they have run once on a PR
3. **Environments**:
   - `dev` — Deployment branches: *Selected branches* → `main`
   - `prod` — Deployment branches: `main`; **Required reviewers: you**; leave *Prevent self-review* **off**
4. **Code security**: enable *Secret scanning* and *Push protection*, *Dependabot alerts*.
5. **Actions → General**: *Workflow permissions* = Read repository contents; *Require approval for all external contributors*.

✅ Check: try `git push origin main` directly from your machine — it must be **rejected**.

---

## 2. Azure — storage, Key Vault, Data Factory (dev + prod)

Create a free account at azure.microsoft.com/free if you don't have one, then:

```bash
az login
az account show -o table                       # confirm the right subscription

# New subscriptions must register these providers once (takes ~1 min each)
for p in Microsoft.DataFactory Microsoft.Storage Microsoft.KeyVault Microsoft.EventGrid; do
  az provider register --namespace $p --wait
done

# Cost guard-rail: email at 80% of $10/month (portal: Cost Management → Budgets also works)
az consumption budget create --budget-name dpl-lab --amount 10 --time-grain Monthly \
  --start-date $(date +%Y-%m-01) --end-date 2027-12-31 --category Cost 2>/dev/null \
  || echo "create the budget in the portal: Cost Management → Budgets"

az group create -n rg-dpl-dev  -l $LOCATION
az group create -n rg-dpl-prod -l $LOCATION
```

### 2a. GitHub → Azure login without secrets (OIDC)

```bash
bash bootstrap/azure/oidc.sh
```
It prints, per environment, `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID` and
`githubSpObjectId`. Keep the output open.

### 2b. Deploy storage + Key Vault + ADF for each environment

```bash
ME=$(az ad signed-in-user show --query id -o tsv)

az deployment group create -g rg-dpl-dev  -f bootstrap/azure/main.bicep \
  -p env=dev  suffix=$SUFFIX adminObjectId=$ME githubSpObjectId=<dev githubSpObjectId>  -o table

az deployment group create -g rg-dpl-prod -f bootstrap/azure/main.bicep \
  -p env=prod suffix=$SUFFIX adminObjectId=$ME githubSpObjectId=<prod githubSpObjectId> -o table

# Outputs you will need later
az deployment group show -g rg-dpl-dev  -n main --query properties.outputs -o json
az deployment group show -g rg-dpl-prod -n main --query properties.outputs -o json
```

Creates per env: `stdpl<suffix><env>` (ADLS Gen2, container `landing`, no account keys),
`kv-dpl-<suffix>-<env>`, `adf-dpl-<suffix>-<env>` (with managed identity) and role assignments.

### 2c. Connect **dev** Data Factory to GitHub (prod is never Git-connected)

Portal → `adf-dpl-<suffix>-dev` → **Launch Studio** → **Manage → Source control → Git configuration → Configure**:

| Field | Value |
|---|---|
| Repository type | GitHub (authorize the *AzureDataFactory* app for your account) |
| Repository | `Data-Pipeline-Lab-` |
| Collaboration branch | `main` |
| Root folder | `/adf` |
| Import existing resources | No (factory is empty) |
| Disable publish (from ADF Studio) | **Yes** if offered — publishing is done by CI |

From now on you author ADF on a **feature branch** in Studio (branch dropdown → *New branch*), click
**Save all** (= git commit), then **Create pull request**. Studio cannot write to `main` (ruleset).

✅ Check:
- `az datafactory show -g rg-dpl-dev -n adf-dpl-$SUFFIX-dev --query identity.principalId -o tsv` prints an ID
- Portal → storage account → Containers shows `landing`
- In Studio, the Git branch dropdown shows `main`

---

## 3. Snowflake — database, schemas, roles, service users

1. Sign up at signup.snowflake.com: edition **Enterprise**, cloud **Microsoft Azure**, region **West US 2
   (Washington)** — same region as Azure, so no cross-region transfer.
2. Snowsight → **Projects → Worksheets → +** and run, in order (each file top to bottom):
   1. `bootstrap/snowflake/00_account.sql` → note the `SNOWFLAKE_ACCOUNT` value it returns (`ORGNAME-ACCOUNTNAME`)
   2. `bootstrap/snowflake/10_env_dev.sql`
   3. `bootstrap/snowflake/10_env_prod.sql`
3. On your machine, generate keys (stored in `~/.snowflake-keys`, never in the repo):
   ```bash
   bash bootstrap/snowflake/keys.sh
   ```
   Paste the printed `USE ROLE SECURITYADMIN; ALTER USER ... SET RSA_PUBLIC_KEY = ...` lines into Snowsight and run.

Result, per environment (`DEV` / `PROD`):

```
VULN_MGMT_<ENV>
├── RAW_VULN_MANAGEMENT      raw tool payloads (VARIANT)         ← ADF writes (VULN_LOADER)
├── CURATED_VULN_MANAGEMENT  typed tables built by procedures    ← procedures write (VULN_LOADER calls them)
├── BYOD_INFOSEC             published views for reporting       ← Tableau reads (VULN_REPORTER)
└── SCHEMACHANGE             deployment history                  ← CI (VULN_DEPLOYER)
```

✅ Check:
```bash
pip install "snowflake-connector-python>=3.12"
python bootstrap/snowflake/test_login.py <ORGNAME-ACCOUNTNAME> dev
python bootstrap/snowflake/test_login.py <ORGNAME-ACCOUNTNAME> prod
```
Expected (schemas each user can see):
- deployer → `BYOD_INFOSEC, CURATED_VULN_MANAGEMENT, INFORMATION_SCHEMA, RAW_VULN_MANAGEMENT, SCHEMACHANGE`
- loader → `CURATED_VULN_MANAGEMENT, INFORMATION_SCHEMA, RAW_VULN_MANAGEMENT`
- reporter → `BYOD_INFOSEC, INFORMATION_SCHEMA`

---

## 4. Wire it together

### 4a. Let Snowflake read the Azure `landing` containers

1. Edit the three placeholders in `bootstrap/snowflake/20_storage_integration.sql`
   (tenant ID from `az account show --query tenantId -o tsv`; storage account names from step 2b) and run it.
2. From the `DESC STORAGE INTEGRATION` output, open **AZURE_CONSENT_URL** in a browser → *Accept*.
3. Grant Snowflake's app read access on each container (`AZURE_MULTI_TENANT_APP_NAME` is shown by DESC; use the part before `_`):
   ```bash
   SF_SP=$(az ad sp list --display-name "<AZURE_MULTI_TENANT_APP_NAME before _>" --query "[0].id" -o tsv)
   for env in dev prod; do
     ST=$(az storage account show -g rg-dpl-$env -n stdpl$SUFFIX$env --query id -o tsv)
     az role assignment create --assignee-object-id $SF_SP --assignee-principal-type ServicePrincipal \
       --role "Storage Blob Data Reader" --scope "$ST/blobServices/default/containers/landing"
   done
   ```
   (Role assignments can take ~5 minutes to apply.)

✅ Check: in Snowsight as ACCOUNTADMIN
`SELECT SYSTEM$VALIDATE_STORAGE_INTEGRATION('AZ_LANDING_DEV','azure://stdpl<suffix>dev.blob.core.windows.net/landing/','validate.txt','read');`
returns `"status":"success"` for read (write/delete are expected to fail — read-only by design).

### 4b. ADF's Snowflake key → Key Vault

```bash
for env in dev prod; do
  KV=kv-dpl-$SUFFIX-$env
  az keyvault secret set --vault-name $KV -n snowflake-loader-private-key \
     --file ~/.snowflake-keys/svc_vuln_loader_$env.p8 -o none
  az keyvault secret set --vault-name $KV -n snowflake-loader-passphrase \
     --file ~/.snowflake-keys/svc_vuln_loader_$env.pass -o none
done
```

### 4c. GitHub environment variables and secrets

Repo → Settings → Environments → `dev` (repeat for `prod` with the prod values):

| Kind | Name | Value |
|---|---|---|
| Variable | `AZURE_CLIENT_ID` / `AZURE_TENANT_ID` / `AZURE_SUBSCRIPTION_ID` | from `oidc.sh` |
| Variable | `AZURE_RESOURCE_GROUP` | `rg-dpl-dev` |
| Variable | `ADF_NAME` | `adf-dpl-<suffix>-dev` |
| Variable | `STORAGE_ACCOUNT` | `stdpl<suffix>dev` |
| Variable | `SNOWFLAKE_ACCOUNT` | `ORGNAME-ACCOUNTNAME` |
| Variable | `SNOWFLAKE_DATABASE` | `VULN_MGMT_DEV` |
| Secret | `SNOWFLAKE_PRIVATE_KEY` | contents of `~/.snowflake-keys/svc_vuln_deployer_dev.p8` |
| Secret | `SNOWFLAKE_PRIVATE_KEY_PASSPHRASE` | contents of `~/.snowflake-keys/svc_vuln_deployer_dev.pass` |

With `gh`:
```bash
for env in dev prod; do
  gh secret set SNOWFLAKE_PRIVATE_KEY            --env $env --repo $REPO < ~/.snowflake-keys/svc_vuln_deployer_$env.p8
  gh secret set SNOWFLAKE_PRIVATE_KEY_PASSPHRASE --env $env --repo $REPO < ~/.snowflake-keys/svc_vuln_deployer_$env.pass
done
gh variable set SNOWFLAKE_DATABASE --env dev  --repo $REPO --body VULN_MGMT_DEV
gh variable set SNOWFLAKE_DATABASE --env prod --repo $REPO --body VULN_MGMT_PROD
# ...and the other variables in the table
```

✅ Check: Settings → Environments shows both environments with 2 secrets and 7 variables each.

---

## 5. Tableau Cloud — do this when the Tableau phase starts

1. Start the Tableau Cloud trial and install Tableau Desktop (trial). Install the **Snowflake ODBC driver 3.4.0+**
   (needed for key-pair auth).
2. In Tableau Cloud → **Explore → New → Project**: `Data Pipeline Lab - Dev` and `Data Pipeline Lab - Prod`.
   On each: *Permissions → Lock to project* so content can't carry its own permissions.
3. **My Account Settings → Saved Credentials → Snowflake → Add**: key-pair auth, user `SVC_VULN_REPORTER_DEV`
   (and `_PROD`), role `VULN_REPORTER_<ENV>`, upload the `.p8`, enter the passphrase.
4. **My Account Settings → Personal Access Tokens** → create `github-actions`.
5. GitHub environments `dev` and `prod`: variables `TABLEAU_SERVER_URL` (e.g. `https://prod-useast-b.online.tableau.com`),
   `TABLEAU_SITE` (site content URL), `TABLEAU_PROJECT` (`Data Pipeline Lab - Dev` / `- Prod`);
   secrets `TABLEAU_PAT_NAME`, `TABLEAU_PAT_SECRET`.

✅ Check: in Desktop, connect to Snowflake with key-pair as `SVC_VULN_REPORTER_DEV` → only `BYOD_INFOSEC` is visible.

---

## Teardown (when the lab is done)

```bash
az group delete -n rg-dpl-dev  --yes --no-wait
az group delete -n rg-dpl-prod --yes --no-wait
```
Key Vaults are soft-deleted for 7 days (`az keyvault purge` to remove now). Snowflake/Tableau trials just expire.
