param environment string
param location string
param resourceGroupName string

targetScope = 'subscription'

resource iacServiceCodeRG 'Microsoft.Resources/resourceGroups@2021-01-01' = {
  name: resourceGroupName
  location: location
  tags: {
    Enviornment: environment
  }
}
