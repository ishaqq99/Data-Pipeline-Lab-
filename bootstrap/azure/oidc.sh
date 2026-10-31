#!/usr/bin/env bash
# ONE-TIME: create one Entra app per environment that GitHub Actions can log in as, with
# NO client secret (OpenID Connect federation). Only workflow jobs that declare
# `environment: dev` (or prod) in THIS repo can obtain a token for that app.
# Requires: az login (an account that can create app registrations).
set -euo pipefail

REPO="${REPO:-ishaqq99/Data-Pipeline-Lab-}"   # owner/name, exact (note the trailing hyphen)

TENANT_ID=$(az account show --query tenantId -o tsv)
SUB_ID=$(az account show --query id -o tsv)

for env in dev prod; do
  name="gh-data-pipeline-lab-$env"
  app_id=$(az ad app list --display-name "$name" --query "[0].appId" -o tsv)
  if [[ -z "$app_id" ]]; then
    app_id=$(az ad app create --display-name "$name" --query appId -o tsv)
  fi
  sp_oid=$(az ad sp show --id "$app_id" --query id -o tsv 2>/dev/null \
           || az ad sp create --id "$app_id" --query id -o tsv)

  cred="github-env-$env"
  if ! az ad app federated-credential list --id "$app_id" --query "[].name" -o tsv | grep -qx "$cred"; then
    az ad app federated-credential create --id "$app_id" --parameters "{
      \"name\": \"$cred\",
      \"issuer\": \"https://token.actions.githubusercontent.com\",
      \"subject\": \"repo:$REPO:environment:$env\",
      \"audiences\": [\"api://AzureADTokenExchange\"]
    }" > /dev/null
  fi

  echo "== $env =="
  echo "  GitHub environment '$env' variables:"
  echo "    AZURE_CLIENT_ID=$app_id"
  echo "    AZURE_TENANT_ID=$TENANT_ID"
  echo "    AZURE_SUBSCRIPTION_ID=$SUB_ID"
  echo "  Bicep parameter githubSpObjectId=$sp_oid"
done
