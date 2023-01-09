param environment string
param prefix string
param locationShortName string
param workspaceSkuName string
param buildAgentIpAddress string
param buildAgentModernPlatformsIpAddress string
param applicationInsightsKind string
param storageAccountSku object
param blobContainers array
param sqlServerSId string
param sqlLogin string
param sqlDatabaseSku object
param appServicePlanSku object
param keyVaultSku object
param location string
param subscriptionId string
param apificationPepGroupIds array
param apificationPepDnsConfigName string
param storagePepGroupIds array
param storagePepDnsConfigName string
param sqlServerPepGroupIds array
param sqlServerPepDnsConfigName string
param webTestsLocations array
param virtualNetworkAddressPrefix string
param subnetAddressPrefix string
param keyVaultSubnetAddressPrefix string
param serviceCodeWebAppName string
param organisationAlertLogicAppIp array
param logicMonitorAppIp array

var resourceGroupName = 'rg-servicescode-${toLower(prefix)}-${toLower(environment)}-${toLower(location)}'
var workspaceName = 'law${toLower(prefix)}${toLower(locationShortName)}${toLower(environment)}'
var applicationInsightsName = 'ai-${toLower(prefix)}-${toLower(locationShortName)}-${toLower(environment)}'
var networkSecurityGroupName = 'nsg-${toLower(prefix)}-${toLower(locationShortName)}-${toLower(environment)}'
var virtualNetworkName = 'vnet-${toLower(prefix)}-${toLower(locationShortName)}-${toLower(environment)}'
var subnetName = 'subnet-${toLower(prefix)}-${toLower(locationShortName)}-${toLower(environment)}'
var keyVaultSubnetName = 'kvsubnet-${toLower(prefix)}-${toLower(locationShortName)}-${toLower(environment)}'
var storageAccountName = 'stg${toLower(prefix)}${toLower(locationShortName)}${toLower(environment)}'
var sqlServerName = 'server${toLower(prefix)}${toLower(locationShortName)}${toLower(environment)}'
var sqlDbName = 'db-${toLower(prefix)}-${toLower(locationShortName)}-${toLower(environment)}'
var privateDnsZonesName = 'dns${toLower(prefix)}${toLower(locationShortName)}${toLower(environment)}.azurewebsites.net'
var logicAppMailName = 'mailla-${toLower(prefix)}-${toLower(locationShortName)}-${toLower(environment)}'
var logicAppManualName = 'manualla-${toLower(prefix)}-${toLower(locationShortName)}-${toLower(environment)}'
var logicAppMonitorName = 'monitorla-${toLower(prefix)}-${toLower(locationShortName)}-${toLower(environment)}'
var logicAppOrganisationAlertName = 'organisationalertla-${toLower(prefix)}-${toLower(locationShortName)}-${toLower(environment)}'
var appServicePlanName = 'asp-${toLower(prefix)}-${toLower(locationShortName)}-${toLower(environment)}'
var webAppName = 'services-devops-wa-${toLower(prefix)}-${toLower(locationShortName)}-${toLower(environment)}'
var keyVaultName = 'kv${toLower(prefix)}${toLower(locationShortName)}${toLower(environment)}'
var apificationPrivateEndpointName = 'apification-${toLower(prefix)}-${toLower(locationShortName)}-${toLower(environment)}'
var storagePrivateEndpointName = 'storage-pep-${toLower(prefix)}-${toLower(locationShortName)}-${toLower(environment)}'
var sqlServerPrivateEndpointName = 'server-pep-${toLower(prefix)}-${toLower(locationShortName)}-${toLower(environment)}'
var applicationInsightsWebTestsName = 'at-${toLower(prefix)}-${toLower(locationShortName)}-${toLower(environment)}'

targetScope = 'subscription'

//Resource group deployment 
module servicesCodeRG './.bicep/resourceGroup.bicep' = {
  scope: subscription(subscriptionId)
  name: 'resourceGroup${prefix}'
  params: {
    resourceGroupName: resourceGroupName
    environment: environment
    location: location
  }
}

//Log analytics workspace deployment
module logAnalyticsWorkspace '.bicep/logAnalyticsWorkspace.bicep' = {
  scope: resourceGroup(resourceGroupName)
  name: 'logAnalyticsWorkspaceDeploy'
  params: {
    workspaceName: workspaceName
    workspaceSkuName: workspaceSkuName
  }
  dependsOn: [
    servicesCodeRG
  ]
}

//Application insights deployment
module applicationInsights '.bicep/applicationInsights.bicep' = {
  scope: resourceGroup(resourceGroupName)
  name: 'applicationInsightsDeploy'
  params: {
    applicationInsightsName: applicationInsightsName
    workspaceName: logAnalyticsWorkspace.outputs.workspaceName
    environment: environment
    applicationInsightsKind: applicationInsightsKind
  }
  dependsOn: [
    servicesCodeRG
  ]
}

//Network security group deployment
module networkSecurityGroup '.bicep/networkSecurityGroup.bicep' = {
  scope: resourceGroup(resourceGroupName)
  name: 'networkSecurityGroupDeploy'
  params: {
    networkSecurityGroupName: networkSecurityGroupName
    environment: environment
  }
  dependsOn: [
    servicesCodeRG
  ]
}

//Virtual network deployment
module virtualNetwork '.bicep/virtualNetwork.bicep' = {
  scope: resourceGroup(resourceGroupName)
  name: 'virtualNetworkDeploy'
  params: {
    environment: environment
    virtualNetworkName: virtualNetworkName
    networkSecurityGroupName: networkSecurityGroup.outputs.networkSecurityGroupName
    subnetName: subnetName
    keyVaultSubnetName: keyVaultSubnetName
    virtualNetworkAddressPrefix: virtualNetworkAddressPrefix
    subnetAddressPrefix: subnetAddressPrefix
    keyVaultSubnetAddressPrefix: keyVaultSubnetAddressPrefix
  }
  dependsOn: [
    servicesCodeRG
  ]
}

//SQL deployment
module sql '.bicep/sql.bicep' = {
  scope: resourceGroup(resourceGroupName)
  name: 'sqlDeploy'
  params: {
    sqlServerName: sqlServerName
    environment: environment
    sqlServerSId: sqlServerSId
    sqlDbName: sqlDbName
    sqlLogin: sqlLogin
    subnetId: virtualNetwork.outputs.subnetId
    sqlDatabaseSku: sqlDatabaseSku
  }
  dependsOn: [
    servicesCodeRG
  ]
}

//Web app deployment
module webApp '.bicep/webApp.bicep' = {
  scope: resourceGroup(resourceGroupName)
  name: 'webAppDeploy'
  params: {
    appServicePlanName: appServicePlan.outputs.appServicePlanName
    environment: environment
    subnetId: virtualNetwork.outputs.subnetId
    webAppName: webAppName
    virtualNetworkName: virtualNetwork.outputs.virtualNetworkName
    buildAgentIpAddress: buildAgentIpAddress
    buildAgentModernPlatformsIpAddress: buildAgentModernPlatformsIpAddress
    appInsightName: applicationInsights.outputs.applicationInsightsName
    keyVaultName: keyVaultName
  }
  dependsOn: [
    servicesCodeRG
  ]
}

//Web app deployment
module serviceCodeWebApp './.bicep/servicesCodeWebApp.bicep' = {
  scope: resourceGroup(resourceGroupName)
  name: 'serviceCodeWebAppDeploy'
  params: {
    appServicePlanName: appServicePlan.outputs.appServicePlanName
    environment: environment
    webAppName: serviceCodeWebAppName
    virtualNetworkName: virtualNetwork.outputs.virtualNetworkName
  }
  dependsOn: [
    servicesCodeRG
  ]
}

//Mail Alert Logic app deployment
module logicMailApp '.bicep/logicApp.bicep' = {
  scope: resourceGroup(resourceGroupName)
  name: 'logicMailAppDeploy'
  params: {
    logicAppName: logicAppMailName
    environment: environment
    ipAddresses: webApp.outputs.ipAddresses
  }
  dependsOn: [
    servicesCodeRG
  ]
}

//Manual Intervention Logic app deployment
module logicManualApp '.bicep/logicApp.bicep' = {
  scope: resourceGroup(resourceGroupName)
  name: 'logicManualAppDeploy'
  params: {
    logicAppName: logicAppManualName
    environment: environment
    ipAddresses: webApp.outputs.ipAddresses
  }
  dependsOn: [
    servicesCodeRG
    logicMailApp
  ]
}

//Monitor Logic app deployment
module logicMonitorApp '.bicep/logicAppMonitor.bicep' = {
  scope: resourceGroup(resourceGroupName)
  name: 'logicMonitorAppDeploy'
  params: {
    logicAppName: logicAppMonitorName
    environment: environment
    ipAddresses: webApp.outputs.ipAddresses
    additionalIp: logicMonitorAppIp
  }
  dependsOn: [
    servicesCodeRG
    logicManualApp
  ]
}

//OrganisationAlert Logic app deployment
module organisationAlertLogicApp '.bicep/logicAppMonitor.bicep' = {
  scope: resourceGroup(resourceGroupName)
  name: 'organisationAlertLogicAppDeploy'
  params: {
    logicAppName: logicAppOrganisationAlertName
    environment: environment
    ipAddresses: webApp.outputs.ipAddresses
    additionalIp: organisationAlertLogicAppIp
  }
  dependsOn: [
    servicesCodeRG
    logicMonitorApp
  ]
}

//Storage account deployment
module storageAccount '.bicep/storageAccount.bicep' = {
  scope: resourceGroup(resourceGroupName)
  name: 'storageAccountDeploy'
  params: {
    environment: environment
    storageAccountName: storageAccountName
    storageAccountSku: storageAccountSku
    blobContainers: blobContainers
    keyVaultSubnetId: virtualNetwork.outputs.keyVaultSubnetId
    sqlServerName: sql.outputs.sqlServerName
    subnetId: virtualNetwork.outputs.subnetId
    virtualNetworkName: virtualNetwork.outputs.virtualNetworkName
    mailLogicAppId: logicMailApp.outputs.logicAppId
    manualLogicAppId: logicManualApp.outputs.logicAppId
    sqlServerId: sql.outputs.serverId
  }
  dependsOn: [
    servicesCodeRG
  ]
}

//Diagnostic settings for logic app
module mailLogicAppDiagnosticSettings '.bicep/logicAppDiagnosticSettings.bicep' = {
  scope: resourceGroup(resourceGroupName)
  name: 'mailLogicAppDiagnosticSettingsDeploy'
  params: {
    logicAppName: logicMailApp.outputs.logicAppName
    storageAccountName: storageAccount.outputs.storageAccountName
  }
}

//Diagnostic settings for logic app
module manualLogicAppDiagnosticSettings '.bicep/logicAppDiagnosticSettings.bicep' = {
  scope: resourceGroup(resourceGroupName)
  name: 'manualLogicAppDiagnosticSettingsDeploy'
  params: {
    logicAppName: logicManualApp.outputs.logicAppName
    storageAccountName: storageAccount.outputs.storageAccountName
  }
  dependsOn: [
    mailLogicAppDiagnosticSettings
  ]
}

//Diagnostic settings for logic app
module monitorLogicAppDiagnosticSettings '.bicep/logicAppDiagnosticSettings.bicep' = {
  scope: resourceGroup(resourceGroupName)
  name: 'monitorLogicAppDiagnosticSettingsDeploy'
  params: {
    logicAppName: logicMonitorApp.outputs.logicAppName
    storageAccountName: storageAccount.outputs.storageAccountName
  }
  dependsOn: [
    manualLogicAppDiagnosticSettings
  ]
}

//Diagnostic settings for logic app
module organisationalLogicAppDiagnosticSettings '.bicep/logicAppDiagnosticSettings.bicep' = {
  scope: resourceGroup(resourceGroupName)
  name: 'organisationalLogicAppDiagnosticSettingsDeploy'
  params: {
    logicAppName: organisationAlertLogicApp.outputs.logicAppName
    storageAccountName: storageAccount.outputs.storageAccountName
  }
  dependsOn: [
    monitorLogicAppDiagnosticSettings
  ]
}

//Diagnostic settings for web app
module webAppDiagnosticSettings '.bicep/webAppDiagnosticSettings.bicep' = {
  scope: resourceGroup(resourceGroupName)
  name: 'webAppDiagnosticSettingDeploy'
  params: {
    storageAccountName: storageAccount.outputs.storageAccountName
    webAppName: webApp.outputs.webAppName
  }
}

//Diagnostic settings for servicesCode web app
module webAppServicesCodeDiagnosticSettings '.bicep/webAppServicesCodeDiagnosticSettings.bicep' = {
  scope: resourceGroup(resourceGroupName)
  name: 'webAppServicesCodeDiagnosticSettingDeploy'
  params: {
    storageAccountName: storageAccount.outputs.storageAccountName
    webAppName: serviceCodeWebApp.outputs.webAppName
  }
}

//Diagnostic Settings for SQL Db
module SqlDbDiagnosticSettings '.bicep/sqlDiagnosticSettings.bicep' = {
  scope: resourceGroup(resourceGroupName)
  name: 'SqlDbDiagnosticSettingsDeploy'
  params: {
    storageAccountName: storageAccount.outputs.storageAccountName
    sqlDbName: sql.outputs.sqlDbName
    sqlServerName: sql.outputs.sqlServerName
  }
  dependsOn: [
    storageAccount
  ]
}

//sql auditing settings deployment
module auditSettings '.bicep/sqlAuditSettings.bicep' = {
  scope: resourceGroup(resourceGroupName)
  name: 'sqlAuditSSettingsDeploy'
  params: {
    sqlServerName: sql.outputs.sqlServerName
    storageAccountName: storageAccount.outputs.storageAccountName
  }
}

//App service plan deployment
module appServicePlan '.bicep/appServicePlan.bicep' = {
  scope: resourceGroup(resourceGroupName)
  name: 'appServicePlanDeploy'
  params: {
    appServicePlanName: appServicePlanName
    appServicePlanSku: appServicePlanSku
    environment: environment
  }
  dependsOn: [
    servicesCodeRG
  ]
}

//Key vault deployment
module keyVault '.bicep/keyVault.bicep' = {
  scope: resourceGroup(resourceGroupName)
  name: 'keyVaultDeploy'
  params: {
    keyVaultName: keyVaultName
    environment: environment
    keyVaultSku: keyVaultSku
    ipAddresses: webApp.outputs.ipAddresses
    subnetId: virtualNetwork.outputs.subnetId
    keyVaultSubnetId: virtualNetwork.outputs.keyVaultSubnetId
    storageAccountName: storageAccount.outputs.storageAccountName
  }
  dependsOn: [
    servicesCodeRG
  ]
}

//Key vault access for web app
module keyVaultAccess '.bicep/keyVaultAccessPolicy.bicep' = {
  scope: resourceGroup(resourceGroupName)
  name: 'keyVaultAccessDeploy'
  params: {
    keyVaultName: keyVault.outputs.keyVaultName
    keyVaultObjectId: webApp.outputs.webAppPrincipalId
  }
  dependsOn: [
    servicesCodeRG
  ]
}

//Private DNS deployment 
module privateDNS '.bicep/privateDNS.bicep' = {
  scope: resourceGroup(resourceGroupName)
  name: 'privateDNSDeploy'
  params: {
    privateDnsZonesName: privateDnsZonesName
    virtualNetworkName: virtualNetwork.outputs.virtualNetworkName
    environment: environment
  }
  dependsOn: [
    servicesCodeRG
  ]
}

//Apification Private end point deployment
module privateEndPoint '.bicep/privateEndPoint.bicep' = {
  scope: resourceGroup(resourceGroupName)
  name: 'apificationPrivateEndPointDeploy'
  params: {
    privateEndpointName: apificationPrivateEndpointName
    privateLinkServiceId: keyVault.outputs.keyVaultId
    subnetId: virtualNetwork.outputs.keyVaultSubnetId
    environment: environment
    privateDnsZoneId: privateDNS.outputs.privateDnsZoneId
    groupIds: apificationPepGroupIds
    dnsConfigName: apificationPepDnsConfigName
  }
  dependsOn: [
    servicesCodeRG
  ]
}

//storage Private end point deployment
module storagePrivateEndPoint '.bicep/privateEndPoint.bicep' = {
  scope: resourceGroup(resourceGroupName)
  name: 'storagePrivateEndPointDeploy'
  params: {
    privateEndpointName: storagePrivateEndpointName
    privateLinkServiceId: storageAccount.outputs.storageAccountId
    subnetId: virtualNetwork.outputs.keyVaultSubnetId
    environment: environment
    privateDnsZoneId: privateDNS.outputs.privateDnsZoneId
    groupIds: storagePepGroupIds
    dnsConfigName: storagePepDnsConfigName
  }
  dependsOn: [
    servicesCodeRG
    privateEndPoint
  ]
}

//sql server Private end point deployment
module sqlServerPrivateEndPoint '.bicep/privateEndPoint.bicep' = {
  scope: resourceGroup(resourceGroupName)
  name: 'sqlServerPrivateEndPointDeploy'
  params: {
    privateEndpointName: sqlServerPrivateEndpointName
    privateLinkServiceId: sql.outputs.serverId
    subnetId: virtualNetwork.outputs.keyVaultSubnetId
    environment: environment
    privateDnsZoneId: privateDNS.outputs.privateDnsZoneId
    groupIds: sqlServerPepGroupIds
    dnsConfigName: sqlServerPepDnsConfigName
  }
  dependsOn: [
    servicesCodeRG
    storagePrivateEndPoint
  ]
}

//Availability test deployment
module availabilityTestModule '.bicep/availabilityTest.bicep' = {
  scope: resourceGroup(resourceGroupName)
  name: 'availabilityTestDeploy'
  params: {
    applicationInsightsName: applicationInsights.outputs.applicationInsightsName
    applicationInsightsWebTestsName: applicationInsightsWebTestsName
    webAppName: webApp.outputs.webAppName
    webTestsLocations: webTestsLocations
  }
  dependsOn: [
    servicesCodeRG
  ]
}
