param keyVaultName string
param environment string
param keyVaultSku object
param ipAddresses array
param subnetId string
param keyVaultSubnetId string
param storageAccountName string
param location string = resourceGroup().location

resource storageAccountResource 'Microsoft.Storage/storageAccounts@2021-04-01' existing = {
  name: storageAccountName
}

resource keyVaultResource 'Microsoft.KeyVault/vaults@2021-04-01-preview' = {
  name: keyVaultName
  location: location
  tags: {
    Environment: environment
  }
  properties: {
    sku: {
      family: keyVaultSku.family
      name: keyVaultSku.name
    }
    tenantId: subscription().tenantId
    accessPolicies: []
    networkAcls: {
      bypass: 'None'
      defaultAction: 'Deny'
      ipRules: [for ip in ipAddresses: {
        value: '${ip}/32'
      }]
      virtualNetworkRules: [
        {
          id: subnetId
          ignoreMissingVnetServiceEndpoint: false
        }
        {
          id: keyVaultSubnetId
          ignoreMissingVnetServiceEndpoint: false
        }
      ]
    }
  }
}

resource diagnosticSettingWebApp 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'dgSettings'
  scope: keyVaultResource
  properties: {
    logs: [
      {
        category: 'AuditEvent'
        enabled: true
        retentionPolicy: {
          days: 0
          enabled: true
        }
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
        retentionPolicy: {
          days: 0
          enabled: true
        }
      }
    ]
    storageAccountId: storageAccountResource.id
  }
  dependsOn: [
    keyVaultResource
  ]
}

output keyVaultId string = keyVaultResource.id
output keyVaultName string = keyVaultResource.name
