-- =====================================================================================
-- ONE-TIME: let Snowflake read the Azure landing containers. Run AFTER the Azure setup.
-- Replace the three <...> placeholders, run as ACCOUNTADMIN, then follow docs/SETUP.md
-- (open AZURE_CONSENT_URL, then grant the Snowflake app "Storage Blob Data Reader").
-- =====================================================================================
USE ROLE ACCOUNTADMIN;

CREATE STORAGE INTEGRATION IF NOT EXISTS AZ_LANDING_DEV
  TYPE = EXTERNAL_STAGE
  STORAGE_PROVIDER = 'AZURE'
  ENABLED = TRUE
  AZURE_TENANT_ID = '<AZURE_TENANT_ID>'
  STORAGE_ALLOWED_LOCATIONS = ('azure://<DEV_STORAGE_ACCOUNT>.blob.core.windows.net/landing/');

CREATE STORAGE INTEGRATION IF NOT EXISTS AZ_LANDING_PROD
  TYPE = EXTERNAL_STAGE
  STORAGE_PROVIDER = 'AZURE'
  ENABLED = TRUE
  AZURE_TENANT_ID = '<AZURE_TENANT_ID>'
  STORAGE_ALLOWED_LOCATIONS = ('azure://<PROD_STORAGE_ACCOUNT>.blob.core.windows.net/landing/');

-- The deployer creates the external STAGE (code); the integration itself stays infra.
GRANT USAGE ON INTEGRATION AZ_LANDING_DEV  TO ROLE VULN_DEPLOYER_DEV;
GRANT USAGE ON INTEGRATION AZ_LANDING_PROD TO ROLE VULN_DEPLOYER_PROD;

-- Copy AZURE_CONSENT_URL and AZURE_MULTI_TENANT_APP_NAME from each:
DESC STORAGE INTEGRATION AZ_LANDING_DEV;
DESC STORAGE INTEGRATION AZ_LANDING_PROD;
