param networkSecurityGroupName string
param environment string
param location string = resourceGroup().location

resource networkSecurityGroupResource 'Microsoft.Network/networkSecurityGroups@2019-09-01' = {
  name: networkSecurityGroupName
  location: location
  tags: {
    Environment: environment
  }
  properties: {
    securityRules: []
  }
}

output networkSecurityGroupName string = networkSecurityGroupResource.name
