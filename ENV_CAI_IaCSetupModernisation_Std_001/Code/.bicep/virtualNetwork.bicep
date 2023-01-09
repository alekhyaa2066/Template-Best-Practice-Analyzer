param virtualNetworkName string
param environment string
param networkSecurityGroupName string
param subnetName string
param keyVaultSubnetName string
param virtualNetworkAddressPrefix string
param subnetAddressPrefix string
param keyVaultSubnetAddressPrefix string
param location string = resourceGroup().location

resource networkSecurityGroupResource 'Microsoft.Network/networkSecurityGroups@2019-09-01' existing = {
  name: networkSecurityGroupName
}

resource virtualNetworkResource 'Microsoft.Network/virtualNetworks@2021-02-01' = {
  name: virtualNetworkName
  location: location
  tags: {
    Environment: environment
  }
  properties: {
    addressSpace: {
      addressPrefixes: [
        virtualNetworkAddressPrefix
      ]
    }
    dhcpOptions: {
      dnsServers: []
    }
    subnets: [
      {
        name: subnetName
        properties: {
          addressPrefix: subnetAddressPrefix
          networkSecurityGroup: {
            id: networkSecurityGroupResource.id
          }
          serviceEndpoints: [
            {
              service: 'Microsoft.KeyVault'
              locations: [
                '*'
              ]
            }
            {
              service: 'Microsoft.Sql'
              locations: [
                '*'
              ]
            }
            {
              service: 'Microsoft.Storage'
              locations: [
                '*'
              ]
            }
          ]
          delegations: [
            {
              name: 'delegation'
              properties: {
                serviceName: 'Microsoft.Web/serverfarms'
              }
            }
          ]
          privateEndpointNetworkPolicies: 'Enabled'
          privateLinkServiceNetworkPolicies: 'Enabled'
        }
      }
      {
        name: keyVaultSubnetName
        properties: {
          addressPrefix: keyVaultSubnetAddressPrefix
          networkSecurityGroup: {
            id: networkSecurityGroupResource.id
          }
          serviceEndpoints: [
            {
              service: 'Microsoft.KeyVault'
              locations: [
                '*'
              ]
            }
            {
              service: 'Microsoft.Storage'
              locations: [
                '*'
              ]
            }
          ]
          delegations: []
          privateEndpointNetworkPolicies: 'Disabled'
          privateLinkServiceNetworkPolicies: 'Enabled'
        }
      }
    ]
  }
}

output subnetId string = '${virtualNetworkResource.id}/subnets/${subnetName}'
output keyVaultSubnetId string = '${virtualNetworkResource.id}/subnets/${keyVaultSubnetName}'
output virtualNetworkName string = virtualNetworkResource.name
