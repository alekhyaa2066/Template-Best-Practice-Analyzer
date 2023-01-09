param sqlDbName string
param storageAccountName string
param sqlServerName string

resource sqlDbResource 'Microsoft.Sql/servers/databases@2021-02-01-preview' existing = {
  name: sqlDbName
}
resource sqlServerResource 'Microsoft.Sql/servers@2021-02-01-preview' existing = {
  name: sqlServerName
}

resource storageAccountResource 'Microsoft.Storage/storageAccounts@2021-04-01' existing = {
  name: storageAccountName
}

resource diagnosticSettingWebApp 'Microsoft.Sql/servers/databases/providers/diagnosticSettings@2021-05-01-preview' = {
  name: '${sqlServerResource.name}/${sqlDbResource.name}/microsoft.insights/diagnosticSettingsName'
  properties: {
    logs: [
      {
        categoryGroup: 'allLogs'
        enabled: true
        retentionPolicy: {
          days: 0
          enabled: false
        }
      }
    ]
    storageAccountId: storageAccountResource.id
  }
}
