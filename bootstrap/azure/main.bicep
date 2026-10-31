// =====================================================================================
// ONE-TIME INFRA per environment — deployed by a human with `az deployment group create`
// (see docs/SETUP.md). Never deployed by the merge pipeline.
// Creates: ADLS Gen2 storage + "landing" container, Key Vault (RBAC), Data Factory with
// system-assigned identity, and the minimum role assignments.
// =====================================================================================
targetScope = 'resourceGroup'

@allowed(['dev', 'prod'])
param env string

@description('3-8 lowercase letters/digits that make the global names unique, e.g. "iq7k2"')
@minLength(3)
@maxLength(8)
param suffix string

param location string = resourceGroup().location

@description('Object ID of the GitHub OIDC service principal for THIS environment (from oidc.sh)')
param githubSpObjectId string

@description('Your own Entra object ID: az ad signed-in-user show --query id -o tsv')
param adminObjectId string

var storageName = 'stdpl${suffix}${env}'
var kvName = 'kv-dpl-${suffix}-${env}'
var adfName = 'adf-dpl-${suffix}-${env}'
var tags = {
  project: 'data-pipeline-lab'
  env: env
}

// Built-in role definition IDs
var roleStorageBlobDataContributor = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
var roleKeyVaultSecretsUser = '4633458b-17de-408a-b874-0445c86b69e6'
var roleKeyVaultSecretsOfficer = 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7'
var roleDataFactoryContributor = '673868aa-7521-48a0-acc6-0f60742d39f5'

resource st 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageName
  location: location
  tags: tags
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    isHnsEnabled: true // ADLS Gen2
    accessTier: 'Hot'
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false // Entra ID only: no account keys / SAS
  }
}

resource blobSvc 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: st
  name: 'default'
}

resource landing 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobSvc
  name: 'landing'
  properties: { publicAccess: 'None' }
}

resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: kvName
  location: location
  tags: tags
  properties: {
    tenantId: tenant().tenantId
    sku: { family: 'A', name: 'standard' }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
    publicNetworkAccess: 'Enabled'
  }
}

resource adf 'Microsoft.DataFactory/factories@2018-06-01' = {
  name: adfName
  location: location
  tags: tags
  identity: { type: 'SystemAssigned' }
  properties: {
    publicNetworkAccess: 'Enabled'
  }
}

// ADF reads Snowflake key + passphrase from Key Vault
resource adfKvSecretsUser 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: kv
  name: guid(kv.id, adf.id, roleKeyVaultSecretsUser)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleKeyVaultSecretsUser)
    principalId: adf.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// You can add/rotate secrets in the vault
resource adminKvOfficer 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: kv
  name: guid(kv.id, adminObjectId, roleKeyVaultSecretsOfficer)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleKeyVaultSecretsOfficer)
    principalId: adminObjectId
    principalType: 'User'
  }
}

// GitHub Actions uploads the daily feed files into "landing"
resource ghLandingWriter 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: landing
  name: guid(landing.id, githubSpObjectId, roleStorageBlobDataContributor)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleStorageBlobDataContributor)
    principalId: githubSpObjectId
    principalType: 'ServicePrincipal'
  }
}

// You can browse files in the portal (shared-key access is disabled)
resource adminBlob 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: st
  name: guid(st.id, adminObjectId, roleStorageBlobDataContributor)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleStorageBlobDataContributor)
    principalId: adminObjectId
    principalType: 'User'
  }
}

// GitHub Actions deploys ADF pipelines (ARM deployments into this resource group)
resource ghAdfDeployer 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, githubSpObjectId, roleDataFactoryContributor)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleDataFactoryContributor)
    principalId: githubSpObjectId
    principalType: 'ServicePrincipal'
  }
}

output storageAccount string = st.name
// Snowflake wants the azure:// scheme with the blob endpoint host
output landingUrl string = replace('${st.properties.primaryEndpoints.blob}landing/', 'https://', 'azure://')
output keyVault string = kv.name
output dataFactory string = adf.name
output dataFactoryId string = adf.id
output dataFactoryPrincipalId string = adf.identity.principalId
