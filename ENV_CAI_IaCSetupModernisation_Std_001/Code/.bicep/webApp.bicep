param appServicePlanName string
param environment string
param subnetId string
param webAppName string
param virtualNetworkName string
param buildAgentIpAddress string
param buildAgentModernPlatformsIpAddress string
param appInsightName string
param keyVaultName string

resource virtualNetworkResource 'Microsoft.Network/virtualNetworks@2021-02-01' existing = {
  name: virtualNetworkName
}

resource appServicePlanResource 'Microsoft.Web/serverFarms@2020-06-01' existing = {
  name: appServicePlanName
}

resource appInsightResource 'microsoft.insights/components@2020-02-02' existing = {
  name: appInsightName
}

resource keyVaultResource 'Microsoft.KeyVault/vaults@2021-04-01-preview' existing = {
  name: keyVaultName
}

resource webAppNameResource 'Microsoft.Web/sites@2021-01-15' = {
  name: webAppName
  tags: {
    Environment: environment
  }
  location: resourceGroup().location
  kind: 'app'
  identity: {
    type: 'SystemAssigned'
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
    }
    httpsOnly: true
    virtualNetworkSubnetId: subnetId
    keyVaultReferenceIdentity: 'SystemAssigned'
  }
}

resource sitesConfig 'Microsoft.Web/sites/config@2021-02-01' = {
  name: '${webAppNameResource.name}/web'
  properties: {
    ipSecurityRestrictions: [
      {
        ipAddress: buildAgentIpAddress
        action: 'Allow'
        tag: 'Default'
        priority: 2
        name: 'Build Agent'
      }
      {
        ipAddress: buildAgentModernPlatformsIpAddress
        action: 'Allow'
        tag: 'Default'
        priority: 3
        name: 'BuildAgentModernPlatforms'
      }
    ]
    appSettings: [
      {
        name: 'APPINSIGHTS_INSTRUMENTATIONKEY'
        value: appInsightResource.properties.InstrumentationKey
      }
      {
        name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
        value: appInsightResource.properties.ConnectionString
      }
      {
        name: 'ApplicationInsightsAgent_EXTENSION_VERSION'
        value: '~2'
      }
      {
        name: 'KeyVaultName'
        value: keyVaultResource.name
      }
      {
        name: 'ANCM_ADDITIONAL_ERROR_PAGE_LINK'
        value: 'https://${webAppName}.scm.azurewebsites.net/detectors?type=tools&name=eventviewer'
      }
      {
        name: 'WEBSITE_RUN_FROM_PACKAGE'
        value: '1'
      }
      {
        name: 'WEBSITE_VNET_ROUTE_ALL'
        value: '1'
      }
      {
        name: 'XDT_MicrosoftApplicationInsights_Mode'
        value: 'default'
      }
    ]
  }
}

resource siteVirtualNetwork 'Microsoft.Web/sites/virtualNetworkConnections@2021-01-15' = {
  name: '${webAppNameResource.name}/vnetConn'
  properties: {
    vnetResourceId: virtualNetworkResource.id
  }
}

resource stagingSlot 'Microsoft.Web/sites/slots@2021-02-01' = {
  name: '${webAppNameResource.name}/staging'
  location: resourceGroup().location
  properties: {
    enabled: true
  }
}

output webAppId string = webAppNameResource.id
output webAppPrincipalId string = webAppNameResource.identity.principalId
var webAppNameIp = webAppNameResource.properties.possibleOutboundIpAddresses
output ipAddresses array = split(webAppNameIp, ',')
output ips string = webAppNameIp
output webAppName string = webAppNameResource.name
