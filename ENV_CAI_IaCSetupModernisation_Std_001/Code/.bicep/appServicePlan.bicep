param appServicePlanName string
param appServicePlanSku object
param environment string
param location string = resourceGroup().location

resource appServicePlanResource 'Microsoft.Web/serverFarms@2020-06-01' = {
  name: appServicePlanName
  location: location
  tags: {
    Environment: environment
  }
  sku: {
    name: appServicePlanSku.name
    tier: appServicePlanSku.tier
    size: appServicePlanSku.size
    family: appServicePlanSku.family
    capacity: appServicePlanSku.capacity
  }
  kind: 'app'
}

output appServicePlanName string = appServicePlanResource.name
