param sqlServerName string
param environment string
param sqlServerSId string
param sqlDbName string
param subnetId string
param sqlLogin string
param sqlDatabaseSku object
param location string = resourceGroup().location

resource sqlServerResource 'Microsoft.Sql/servers@2021-02-01-preview' = {
  name: sqlServerName
  location: location
  tags: {
    Environment: environment
  }
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    publicNetworkAccess: 'Enabled'
    version: '12.0'
    minimalTlsVersion: '1.2'
    administrators: {
      administratorType: 'ActiveDirectory'
      login: sqlLogin
      sid: sqlServerSId
      tenantId: subscription().tenantId
      azureADOnlyAuthentication: true
    }
    restrictOutboundNetworkAccess: 'Disabled'
  }
}

//SQL Virtual Network Rules
resource sqlVirtualNetworkRule 'Microsoft.Sql/servers/virtualNetworkRules@2021-02-01-preview' = {
  name: '${sqlServerResource.name}/newVnetRule1'
  properties: {
    virtualNetworkSubnetId: subnetId
    ignoreMissingVnetServiceEndpoint: false
  }
}

//SQL Server Auditing Policy
resource serverAuditingPolicies 'Microsoft.Sql/servers/auditingPolicies@2014-04-01' = {
  name: '${sqlServerResource.name}/default'
  properties: {
    auditingState: 'Disabled'
  }
}

resource sqlDbResource 'Microsoft.Sql/servers/databases@2021-02-01-preview' = {
  parent: sqlServerResource
  name: sqlDbName
  tags: {
    Environment: environment
  }
  location: location
  sku: {
    name: sqlDatabaseSku.name
    tier: sqlDatabaseSku.tier
    capacity: sqlDatabaseSku.capacity
  }
}

output serverId string = sqlServerResource.id
output sqlServerName string = sqlServerResource.name
output sqlDbName string = sqlDbResource.name
