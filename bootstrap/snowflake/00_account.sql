-- =====================================================================================
-- ONE-TIME ACCOUNT BOOTSTRAP — run by a human in a Snowsight worksheet as ACCOUNTADMIN.
-- This is INFRASTRUCTURE. The CI/CD pipeline never runs anything in bootstrap/.
-- Safe to re-run (IF NOT EXISTS everywhere).
-- =====================================================================================

USE ROLE ACCOUNTADMIN;

-- Cost guard-rail for the trial: notify at 75%, suspend at 100% of 50 credits / month.
CREATE RESOURCE MONITOR IF NOT EXISTS VULN_LAB_RM
  WITH CREDIT_QUOTA = 50
       FREQUENCY = MONTHLY
       START_TIMESTAMP = IMMEDIATELY
  TRIGGERS ON 75 PERCENT DO NOTIFY
           ON 100 PERCENT DO SUSPEND
           ON 110 PERCENT DO SUSPEND_IMMEDIATE;

USE ROLE SYSADMIN;

-- One X-Small warehouse shared by deploy, load and reporting. Suspends after 60 s idle.
CREATE WAREHOUSE IF NOT EXISTS VULN_WH
  WAREHOUSE_SIZE = XSMALL
  AUTO_SUSPEND = 60
  AUTO_RESUME = TRUE
  INITIALLY_SUSPENDED = TRUE
  COMMENT = 'Data-Pipeline-Lab shared warehouse';

USE ROLE ACCOUNTADMIN;
ALTER WAREHOUSE VULN_WH SET RESOURCE_MONITOR = VULN_LAB_RM;

-- Your account identifier (put this in GitHub as SNOWFLAKE_ACCOUNT):
SELECT CURRENT_ORGANIZATION_NAME() || '-' || CURRENT_ACCOUNT_NAME() AS SNOWFLAKE_ACCOUNT;
