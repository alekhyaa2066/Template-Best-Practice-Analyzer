param logicAppName string
param storageAccountName string

resource storageAccountResource 'Microsoft.Storage/storageAccounts@2021-04-01' existing = {
  name: storageAccountName
}

resource logicAppResource 'Microsoft.Logic/workflows@2019-05-01' existing = {
  name: logicAppName
}

resource diagnosticSettingWebApp 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'dgSettings'
  scope: logicAppResource
  properties: {
    logs: [
      {
        category: 'WorkflowRuntime'
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
}
