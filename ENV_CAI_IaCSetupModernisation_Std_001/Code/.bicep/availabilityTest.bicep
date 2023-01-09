param webAppName string
param applicationInsightsWebTestsName string
param webTestsLocations array
param applicationInsightsName string
param location string = resourceGroup().location

resource webAppNameResource 'Microsoft.Web/sites@2021-01-15' existing = {
  name: webAppName
}

resource applicationInsightsResource 'Microsoft.Insights/components@2020-02-02' existing = {
  name: applicationInsightsName
}

resource webTestsResource 'microsoft.insights/webtests@2018-05-01-preview' = {
  name: applicationInsightsWebTestsName
  location: location
  tags: {
    'hidden-link:${applicationInsightsResource.id}': 'Resource'
  }
  properties: {
    SyntheticMonitorId: applicationInsightsWebTestsName
    Name: applicationInsightsWebTestsName
    Enabled: true
    Timeout: 120
    Kind: 'ping'
    Locations: webTestsLocations
    Configuration: {
      WebTest: '<WebTest         Name="${applicationInsightsWebTestsName}"         Id=""         Enabled="True"         CssProjectStructure=""         CssIteration=""         Timeout="120"         WorkItemIds=""         xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010"         Description=""         CredentialUserName=""         CredentialPassword=""         PreAuthenticate="True"         Proxy="default"         StopOnError="False"         RecordedResultFile=""         ResultsLocale="">        <Items>        <Request         Method="GET"         Guid=""         Version="1.1"         Url="http://${webAppName}.azurewebsites.net/swagger/index.html"         ThinkTime="0"         Timeout="120"         ParseDependentRequests="False"         FollowRedirects="True"         RecordResult="True"         Cache="False"         ResponseTimeGoal="0"         Encoding="utf-8"         ExpectedHttpStatusCode="200"         ExpectedResponseUrl=""         ReportingName=""         IgnoreHttpStatusCode="False" />        </Items>        </WebTest>'
    }
  }
}
