param logicAppName string
param environment string
param ipAddresses array
param additionalIp array
var concatip = concat(ipAddresses,additionalIp)

param location string = resourceGroup().location

resource logicAppResource 'Microsoft.Logic/workflows@2019-05-01' = {
  name: logicAppName
  location: location
  tags: {
    Environment: environment
  }
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    accessControl: {
      triggers: {
        allowedCallerIpAddresses: [for ip in concatip: {
          addressRange: '${ip}/32'
        }]
      }
    }
    state: 'Enabled'
    definition: {
      '$schema': 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
      contentVersion: '1.0.0.0'
      parameters: {}
      triggers: {}
      outputs: {}
      actions: {}
    }
  }
}

output logicAppId string = logicAppResource.id
output logicAppName string = logicAppResource.name
