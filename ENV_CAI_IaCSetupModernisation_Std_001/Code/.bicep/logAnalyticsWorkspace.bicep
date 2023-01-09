param workspaceName string
param workspaceSkuName string
param location string = resourceGroup().location

resource workspaceResource 'microsoft.operationalinsights/workspaces@2021-06-01' = {
  name: workspaceName
  location: location
  properties: {
    sku: {
      name: workspaceSkuName
    }
  }
}

output workspaceName string = workspaceResource.name
