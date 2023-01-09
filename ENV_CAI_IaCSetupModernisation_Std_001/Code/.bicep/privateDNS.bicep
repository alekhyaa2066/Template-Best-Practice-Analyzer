param privateDnsZonesName string
param virtualNetworkName string
param environment string

resource virtualNetworkResource 'Microsoft.Network/virtualNetworks@2021-02-01' existing = {
  name: virtualNetworkName
}

resource privateDnsZonesResource 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: privateDnsZonesName
  tags: {
    Environment: environment
  }
  location: 'global'
  properties: {}
}

resource privateDnsZonesSOA 'Microsoft.Network/privateDnsZones/SOA@2020-06-01' = {
  name: '${privateDnsZonesResource.name}/@'
}

resource privateDnsZoneVnetLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  name: '${privateDnsZonesResource.name}/vnetLink'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: virtualNetworkResource.id
    }
  }
  dependsOn: [
    virtualNetworkResource
  ]
}

output privateDnsZoneId string = privateDnsZonesResource.id
