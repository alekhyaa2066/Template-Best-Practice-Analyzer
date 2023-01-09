param storageAccountName string
param environment string
param storageAccountSku object
param blobContainers array
param virtualNetworkName string
param subnetId string
param keyVaultSubnetId string
param sqlServerName string
param sqlServerId string
param mailLogicAppId string
param manualLogicAppId string
param location string = resourceGroup().location

resource virtualNetworkResource 'Microsoft.Network/virtualNetworks@2021-02-01' existing = {
  name: virtualNetworkName
}

resource sqlServerResource 'Microsoft.Sql/servers@2021-02-01-preview' existing = {
  name: sqlServerName
}

resource storageAccountResource 'Microsoft.Storage/storageAccounts@2021-04-01' = {
  name: storageAccountName
  location: location
  tags: {
    Environment: environment
  }
  sku: {
    name: storageAccountSku.sku
  }
  kind: storageAccountSku.kind
  properties: {
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Allow'
      resourceAccessRules: [
        {
          resourceId: sqlServerId
          tenantId: subscription().tenantId
        }
        {
          resourceId: mailLogicAppId
          tenantId: subscription().tenantId
        }
        {
          resourceId: manualLogicAppId
          tenantId: subscription().tenantId
        }
      ]
      virtualNetworkRules: [
        {
          id: subnetId
        }
        {
          id: keyVaultSubnetId
        }
      ]
    }
    supportsHttpsTrafficOnly: true
  }
}

//Storage Account Container Deployments
resource storageAccountContainers 'Microsoft.Storage/storageAccounts/blobServices/containers@2021-04-01' = [for blobContainer in blobContainers: {
  name: '${storageAccountResource.name}/default/${blobContainer}'
}]

output storageAccountName string = storageAccountResource.name
output storageAccountId string = storageAccountResource.id
