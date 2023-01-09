param sqlServerName string
param storageAccountName string

resource storageAccountResource 'Microsoft.Storage/storageAccounts@2021-04-01' existing = {
  name: storageAccountName
}

resource sqlServerResource 'Microsoft.Sql/servers@2021-02-01-preview' existing = {
  name: sqlServerName
}

resource serverAuditingSettings 'Microsoft.Sql/servers/auditingSettings@2021-02-01-preview' = {
  name: '${sqlServerResource.name}/default'
  properties: {
    retentionDays: 364
    auditActionsAndGroups: [
      'SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP'
      'FAILED_DATABASE_AUTHENTICATION_GROUP'
      'BATCH_COMPLETED_GROUP'
    ]
    isAzureMonitorTargetEnabled: false
    isStorageSecondaryKeyInUse: false
    state: 'Enabled'
    storageEndpoint: storageAccountResource.properties.primaryEndpoints.blob
    storageAccountSubscriptionId: subscription().subscriptionId
    storageAccountAccessKey: storageAccountResource.listKeys().keys[0].value
  }
}
