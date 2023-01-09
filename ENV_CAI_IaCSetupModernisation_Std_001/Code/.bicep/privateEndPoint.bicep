param privateEndpointName string
param privateLinkServiceId string
param subnetId string
param environment string
param privateDnsZoneId string
param groupIds array
param dnsConfigName string
param location string = resourceGroup().location

resource privateEndpointResource 'Microsoft.Network/privateEndpoints@2020-11-01' = {
  name: privateEndpointName
  tags: {
    Environment: environment
  }
  location: location
  properties: {
    privateLinkServiceConnections: [
      {
        name: privateEndpointName
        properties: {
          privateLinkServiceId: privateLinkServiceId
          groupIds: groupIds
          privateLinkServiceConnectionState: {
            status: 'Approved'
          }
        }
      }
    ]
    manualPrivateLinkServiceConnections: []
    subnet: {
      id: subnetId
    }
    customDnsConfigs: []
  }
}

resource apificationPrivateEndpointPrivateDnsZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2020-11-01' = {
  name: '${privateEndpointResource.name}/default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: dnsConfigName
        properties: {
          privateDnsZoneId: privateDnsZoneId
        }
      }
    ]
  }
}
