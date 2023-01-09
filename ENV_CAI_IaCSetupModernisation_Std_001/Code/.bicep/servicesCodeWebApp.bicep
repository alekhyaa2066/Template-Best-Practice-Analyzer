param appServicePlanName string
param environment string
param webAppName string
param virtualNetworkName string
param location string = resourceGroup().location

resource virtualNetworkResource 'Microsoft.Network/virtualNetworks@2021-02-01' existing = {
  name: virtualNetworkName
}

resource appServicePlanResource 'Microsoft.Web/serverFarms@2020-06-01' existing = {
  name: appServicePlanName
}

resource webAppNameResource 'Microsoft.Web/sites@2021-01-15' = {
  name: webAppName
  tags: {
    Environment: environment
  }
  location: location
  kind: 'app'
  identity:{
    type:'SystemAssigned'
  }
  properties: {
    enabled: true
    clientCertEnabled: true
    clientCertMode: 'Optional'
    hostNameSslStates: [
      {
        name: '${webAppName}.azurewebsites.net'
        sslState: 'Disabled'
        hostType: 'Standard'
      }
      {
        name: '${webAppName}.scm.azurewebsites.net'
        sslState: 'Disabled'
        hostType: 'Repository'
      }
    ]
    serverFarmId: appServicePlanResource.id
    siteConfig: {
      alwaysOn: true
      http20Enabled: true
      ftpsState: 'FtpsOnly'
      virtualApplications: [
        {
          virtualPath: '/'
          physicalPath: 'site\\wwwroot'
          preloadEnabled: true
        }
      ]
    }
    httpsOnly: true
    keyVaultReferenceIdentity: 'SystemAssigned'
  }
}

resource sitesConfig 'Microsoft.Web/sites/config@2021-02-01' = {
  name: '${webAppNameResource.name}/web'
  properties: {
    appSettings: [
      {
        name: 'ApplicationInsightsAgent_EXTENSION_VERSION'
        value: '~2'
      }
      {
        name: 'WEBSITE_NODE_DEFAULT_VERSION'
        value: '6.9.1'
      }
    ]
  }
}

output webAppId string = webAppNameResource.id
output webAppName string = webAppNameResource.name
