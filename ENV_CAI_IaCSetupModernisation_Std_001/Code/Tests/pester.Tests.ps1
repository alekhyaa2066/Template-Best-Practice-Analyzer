param (
    [string] $prefix,
    [string] $environment,
    [string] $locationShortName,
    [string] $location,
    [string] $parametersfilePath
)

Describe "Validating all the IaC services code Resources" {
    BeforeAll {        
        if (Test-Path -Path $parametersfilePath) {
            $jsonModuledetails = Get-Content -Path $parametersfilePath
            $details = $jsonModuledetails | ConvertFrom-Json
        } 
    }
    It "Check for IaC services code ResourceGroup" {
        try {
            $resourceGroup = 'rg-servicescode-' + $prefix.ToLower() + '-' + $environment.ToLower() + '-' + $location.ToLower()       
            $getResourceGroup = Get-AzResourceGroup -Name $resourceGroup -WarningAction:SilentlyContinue
        }
        catch {
            Write-output "Failed to validate with error: $($_.exception)."
        } 
        $getResourceGroup.ResourceGroupName | should -Be $resourceGroup      
    }
    It "Check for IaC services code workspace" {
        $resourceGroup = 'rg-servicescode-' + $prefix.ToLower() + '-' + $environment.ToLower() + '-' + $location.ToLower()       
        $workspaceName = 'law' + $prefix.ToLower() + $locationShortName.ToLower() + $environment.ToLower()
        try {
            $getWorkspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $resourceGroup -Name $workspaceName -WarningAction:SilentlyContinue
        }
        catch {
            Write-output "Failed to fetch workspace $($workspaceName),Error:$($_.exception)."
        }
        $getWorkspace.Name | Should -Be $workspaceName
    }
    It "Check for IaC services code applicationInsight " {
        $resourceGroup = 'rg-servicescode-' + $prefix.ToLower() + '-' + $environment.ToLower() + '-' + $location.ToLower()       
        $appInsightName = 'ai-' + $prefix.ToLower() + '-' + $locationShortName.ToLower() + '-' + $environment.ToLower()
        try {
            $getAppInsight = Get-AzApplicationInsights -ResourceGroupName $resourceGroup -Name $appInsightName -WarningAction:SilentlyContinue
        }
        catch {
            Write-output "Failed to fetch appInsight $($appInsightName),Error:$($_.exception)."
        }
        $getAppInsight.Name | Should -Be $appInsightName
    }
    It "Check for IaC services code networkSecurityGroup " {
        $resourceGroup = 'rg-servicescode-' + $prefix.ToLower() + '-' + $environment.ToLower() + '-' + $location.ToLower()       
        $networkSecurityGroupName = 'nsg-' + $prefix.ToLower() + '-' + $locationShortName.ToLower() + '-' + $environment.ToLower()
        try {
            $GetNetworkSecurityGroup = Get-AzNetworkSecurityGroup -ResourceGroupName $resourceGroup -Name $networkSecurityGroupName -WarningAction:SilentlyContinue
        }
        catch {
            Write-output "Failed to fetch networkSecurityGroup $($networkSecurityGroupName),Error:$($_.exception)"
        }
        $GetNetworkSecurityGroup.Name | Should -Be $networkSecurityGroupName
    }
    It "Check for IaC services code virtualNetwork" {
        $resourceGroup = 'rg-servicescode-' + $prefix.ToLower() + '-' + $environment.ToLower() + '-' + $location.ToLower()       
        $virtualNetworkName = 'vnet-' + $prefix.ToLower() + '-' + $locationShortName.ToLower() + '-' + $environment.ToLower()
        try {
            $getVirtualNetwork = Get-AzVirtualNetwork -ResourceGroupName $resourceGroup -Name $virtualNetworkName -WarningAction:SilentlyContinue
        }
        catch {
            Write-output "Failed to fetch virtualNetwork $($virtualNetworkName),Error:$($_.exception)."
        }
        $getVirtualNetwork.Name | Should -Be $virtualNetworkName
    }
    It "Check for IaC services code storageAccount" {
        $resourceGroup = 'rg-servicescode-' + $prefix.ToLower() + '-' + $environment.ToLower() + '-' + $location.ToLower()     
        $storageAccountName = 'stg' + $prefix.ToLower() + $locationShortName.ToLower() + $environment.ToLower()
        try {                
            $getStorageAccount = Get-AzStorageAccount -ResourceGroupName $resourceGroup -Name $storageAccountName -WarningAction:SilentlyContinue
        }
        catch {
            Write-output "Failed to fetch storageAccount $($storageAccountName),Error:$($_.exception)."
        }
        $getStorageAccount.StorageAccountName | Should -Be $storageAccountName
        $getStorageAccount.EnableHttpsTrafficOnly | should -Be $true
    }
    It "Check for IaC services code SQLServer" {
        $resourceGroup = 'rg-servicescode-' + $prefix.ToLower() + '-' + $environment.ToLower() + '-' + $location.ToLower()       
        $sqlServerName = 'server' + $prefix.ToLower() + $locationShortName.ToLower() + $environment.ToLower()
        try {
            $getSQLSServer = Get-AzSqlServer -ResourceGroupName $resourceGroup -ServerName $sqlServerName.toLower()
        }
        catch {
            Write-output "failed to validate SQLServer $($sqlServerName),Error: $($_.exception)"
        }
        $getSQLSServer.ServerName | should -Be $sqlServerName
    }
    It "Check for IaC services code SQL Database" {
        $resourceGroup = 'rg-servicescode-' + $prefix.ToLower() + '-' + $environment.ToLower() + '-' + $location.ToLower() 
        $sqlServerName = 'server' + $prefix.ToLower() + $locationShortName.ToLower() + $environment.ToLower()
        $sqlServerDB = 'db-' + $prefix.ToLower() + '-' + $locationShortName.ToLower() + '-' + $environment.ToLower()
        try {
            $getSQLServerDB = Get-AzSqlDatabase -ResourceGroupName $resourceGroup -ServerName $sqlServerName -DatabaseName $sqlServerDB -WarningAction SilentlyContinue
        }
        catch {
            Write-output "failed to validate sqlDatabase $($sqlServerDB),Error: $($_.exception)"
        }
        $getSQLServerDB.DatabaseName | should -Be $sqlServerDB
    }
    It "Check for IaC services code privateDnsZone " {
        $resourceGroup = 'rg-servicescode-' + $prefix.ToLower() + '-' + $environment.ToLower() + '-' + $location.ToLower() 
        $privateDnsZoneName = 'dns' + $prefix.ToLower() + $locationShortName.ToLower() + $environment.ToLower() + '.azurewebsites.net'
        try {
            $GetPrivateDnsZones = Get-AzPrivateDnsZone -ResourceGroupName $resourceGroup -Name $privateDnsZoneName -WarningAction:SilentlyContinue
        }
        catch {
            Write-output "Failed to fetch PrivateDnsZone $($privateDnsZoneName),Error:$($_.exception)"
            throw $_.exception
        }
        $GetPrivateDnsZones.Name | Should -Be $privateDnsZoneName
        $GetPrivateDnsZones.ResourceGroupName | Should -Be $resourceGroup
    }
    It "Check for IaC services code mailAlertLogicApp" {
        $resourceGroup = 'rg-servicescode-' + $prefix.ToLower() + '-' + $environment.ToLower() + '-' + $location.ToLower() 
        $logicAppName = 'mailla-' + $prefix.ToLower() + '-' + $locationShortName.ToLower() + '-' + $environment.ToLower()
        try {
            $getLogicApp = Get-AzLogicApp -ResourceGroupName $resourceGroup -Name $logicAppName -WarningAction:SilentlyContinue
        }
        catch {
            Write-output "Failed to fetch mailAlertLogicApp $($logicAppName),Error:$($_.exception)."
        }
        $getLogicApp.Name | Should -Be $logicAppName
        $getLogicApp.State | Should -Be 'Enabled'
    }
    It "Check for IaC services code manualLogicApp" {
        $resourceGroup = 'rg-servicescode-' + $prefix.ToLower() + '-' + $environment.ToLower() + '-' + $location.ToLower() 
        $logicAppName = 'mailla-' + $prefix.ToLower() + '-' + $locationShortName.ToLower() + '-' + $environment.ToLower()
        try {
            $getLogicApp = Get-AzLogicApp -ResourceGroupName $resourceGroup -Name $logicAppName -WarningAction:SilentlyContinue
        }
        catch {
            Write-output "Failed to fetch manualLogicApp $($logicAppName),Error:$($_.exception)."
        }
        $getLogicApp.Name | Should -Be $logicAppName
        $getLogicApp.State | Should -Be 'Enabled'
    }
    It "Check for IaC services code logicMonitorApp" {
        $resourceGroup = 'rg-servicescode-' + $prefix.ToLower() + '-' + $environment.ToLower() + '-' + $location.ToLower() 
        $logicAppName = 'monitorla-' + $prefix.ToLower() + '-' + $locationShortName.ToLower() + '-' + $environment.ToLower()
        try {
            $getLogicApp = Get-AzLogicApp -ResourceGroupName $resourceGroup -Name $logicAppName -WarningAction:SilentlyContinue
        }
        catch {
            Write-output "Failed to fetch logicMonitorApp $($logicAppName),Error:$($_.exception)."
        }
        $getLogicApp.Name | Should -Be $logicAppName
        $getLogicApp.State | Should -Be 'Enabled'
    }
    It "Check for IaC services code organisationAlertLogicAppName" {
        $resourceGroup = 'rg-servicescode-' + $prefix.ToLower() + '-' + $environment.ToLower() + '-' + $location.ToLower() 
        $logicAppName = 'organisationalertla-' + $prefix.ToLower() + '-' + $locationShortName.ToLower() + '-' + $environment.ToLower()
        try {
            $getLogicApp = Get-AzLogicApp -ResourceGroupName $resourceGroup -Name $logicAppName -WarningAction:SilentlyContinue
        }
        catch {
            Write-output "Failed to fetch organisationAlertLogicAppName $($logicAppName),Error:$($_.exception)."
        }
        $getLogicApp.Name | Should -Be $logicAppName
        $getLogicApp.State | Should -Be 'Enabled'
    }
    It "Check for IaC services code appServicePlan" {
        $resourceGroup = 'rg-servicescode-' + $prefix.ToLower() + '-' + $environment.ToLower() + '-' + $location.ToLower()
        $appServicePlanName = 'asp-' + $prefix.ToLower() + '-' + $locationShortName.ToLower() + '-' + $environment.ToLower()
        try {
            $getAppServicePlan = Get-AzAppServicePlan -ResourceGroupName $resourceGroup -Name $appServicePlanName -WarningAction:SilentlyContinue
        }
        catch {
            Write-output "Failed to fetch appServicePlan $($appServicePlanName),Error:$($_.exception)."
        }
        $getAppServicePlan.Name | Should -Be $appServicePlanName
    }
    It "Check for IaC services code webApp" {
        $resourceGroup = 'rg-servicescode-' + $prefix.ToLower() + '-' + $environment.ToLower() + '-' + $location.ToLower() 
        $webAppName = 'services-devops-wa-' + $prefix.ToLower() + '-' + $locationShortName.ToLower() + '-' + $environment.ToLower()
        try {                
            $getWebApp = Get-AzWebApp -ResourceGroupName $resourceGroup -Name $webAppName -WarningAction:SilentlyContinue
        }
        catch {
            Write-output "Failed to fetch webApp $($webAppName),Error:$($_.exception)."
        }
        $getWebApp.Name | Should -Be $webAppName
        $getWebApp.HttpsOnly | Should -Be $true
    }
    It "Check for IaC services code serviceCodeWebApp" {
        $resourceGroup = 'rg-servicescode-' + $prefix.ToLower() + '-' + $environment.ToLower() + '-' + $location.ToLower() 
        $webAppName = $details.parameters.serviceCodeWebAppName.value
        try {                
            $getWebApp = Get-AzWebApp -ResourceGroupName $resourceGroup -Name $webAppName -WarningAction:SilentlyContinue
        }
        catch {
            Write-output "Failed to fetch serviceCodeWebApp $($webAppName),Error:$($_.exception)."
        }
        $getWebApp.Name | Should -Be $webAppName
        $getWebApp.HttpsOnly | Should -Be $true
    }
    It "Check for IaC services code keyVault" {
        $resourceGroup = 'rg-servicescode-' + $prefix.ToLower() + '-' + $environment.ToLower() + '-' + $location.ToLower() 
        $keyVaultName = 'kv' + $prefix.ToLower()+ $locationShortName.ToLower() + $environment.ToLower()
        try {                
            $getKeyVault = Get-AzKeyVault -ResourceGroupName $resourceGroup -VaultName $keyVaultName -WarningAction:SilentlyContinue
        }
        catch {
            Write-output "Failed to fetch keyVault $($keyVaultName),Error:$($_.exception)."
        }
        $GetKeyVault.VaultName | should -Be $keyVaultName 
    }
    It "Check for IaC services code apificationPrivateEndpoint " {
        $resourceGroup = 'rg-servicescode-' + $prefix.ToLower() + '-' + $environment.ToLower() + '-' + $location.ToLower() 
        $privateEndpointsName = 'apification-' + $prefix.ToLower() + '-' + $locationShortName.ToLower() + '-' + $environment.ToLower()
        try {
            $GetPrivateEndPoints = Get-AzPrivateEndpoint -Name $privateEndpointsName -ResourceGroupName $resourceGroup -WarningAction:SilentlyContinue
        }
        catch {
            Write-output "Failed to fetch apificationPrivateEndpoint $($privateEndpointsName),Error:$($_.exception)"
            throw $_.exception
        }
        $GetPrivateEndPoints.Name | Should -Be $privateEndpointsName
        $GetPrivateEndPoints.ResourceGroupName | Should -Be $resourceGroup
    }
    It "Check for IaC services code storagePrivateEndpoint " {
        $resourceGroup = 'rg-servicescode-' + $prefix.ToLower() + '-' + $environment.ToLower() + '-' + $location.ToLower() 
        $privateEndpointsName = 'storage-pep-' + $prefix.ToLower() + '-' + $locationShortName.ToLower() + '-' + $environment.ToLower()
        try {
            $GetPrivateEndPoints = Get-AzPrivateEndpoint -Name $privateEndpointsName -ResourceGroupName $resourceGroup -WarningAction:SilentlyContinue
        }
        catch {
            Write-output "Failed to fetch storagePrivateEndpoint $($privateEndpointsName),Error:$($_.exception)"
            throw $_.exception
        }
        $GetPrivateEndPoints.Name | Should -Be $privateEndpointsName
        $GetPrivateEndPoints.ResourceGroupName | Should -Be $resourceGroup
    }
    It "Check for IaC services code sqlServerPrivateEndpoint " {
        $resourceGroup = 'rg-servicescode-' + $prefix.ToLower() + '-' + $environment.ToLower() + '-' + $location.ToLower() 
        $privateEndpointsName = 'server-pep-' + $prefix.ToLower() + '-' + $locationShortName.ToLower() + '-' + $environment.ToLower()
        try {
            $GetPrivateEndPoints = Get-AzPrivateEndpoint -Name $privateEndpointsName -ResourceGroupName $resourceGroup -WarningAction:SilentlyContinue
        }
        catch {
            Write-output "Failed to fetch sqlServerPrivateEndpoint $($privateEndpointsName),Error:$($_.exception)"
            throw $_.exception
        }
        $GetPrivateEndPoints.Name | Should -Be $privateEndpointsName
        $GetPrivateEndPoints.ResourceGroupName | Should -Be $resourceGroup
    }

}