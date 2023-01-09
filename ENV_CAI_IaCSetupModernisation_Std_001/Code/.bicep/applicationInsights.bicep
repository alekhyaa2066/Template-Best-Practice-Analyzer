param applicationInsightsName string
param workspaceName string
param environment string
param applicationInsightsKind string
param location string = resourceGroup().location

resource workspaceResource 'microsoft.operationalinsights/workspaces@2021-06-01' existing = {
  name: workspaceName
}

resource applicationInsightsResource 'Microsoft.Insights/components@2020-02-02' = {
  name: applicationInsightsName
  location: location
  tags: {
    Environment: environment
  }
  kind: applicationInsightsKind
  properties: {
    Application_Type: 'web'
    Flow_Type: 'Bluefield'
    Request_Source: 'rest'
    IngestionMode: 'LogAnalytics'
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
    WorkspaceResourceId: workspaceResource.id
  }
}

output applicationInsightsName string = applicationInsightsResource.name
