param webAppName string
param storageAccountName string

resource webAppNameResource 'Microsoft.Web/sites@2021-01-15' existing = {
  name: webAppName
}

resource storageAccountResource 'Microsoft.Storage/storageAccounts@2021-04-01' existing = {
  name: storageAccountName
}

resource diagnosticSettingWebApp 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'dgSettings'
  scope: webAppNameResource
  properties: {
    logs: [
      {
        category: 'AppServiceAuditLogs'
        enabled: true
        retentionPolicy: {
          days: 90
          enabled: true
        }
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
        retentionPolicy: {
          days: 90
          enabled: true
        }
      }
    ]
    storageAccountId: storageAccountResource.id
  }
}
