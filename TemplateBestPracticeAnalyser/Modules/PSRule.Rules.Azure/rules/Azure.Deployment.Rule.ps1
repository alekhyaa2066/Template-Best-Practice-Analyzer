# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#
# Validation rules for Azure deployments
#

#region Rules

# Synopsis: Avoid outputting sensitive deployment values.
Rule 'Azure.Deployment.OutputSecretValue' -Ref 'AZR-000279' -Type 'Microsoft.Resources/deployments' -Tag @{ release = 'GA'; ruleSet = '2022_06'; 'Azure.WAF/pillar' = 'Security'; } {
    $Assert.Create($PSRule.Issue.Get('PSRule.Rules.Azure.Template.OutputSecretValue'));
}

# Synopsis: Ensure all properties named used for setting a username within a deployment are expressions (e.g. an ARM function not a string)
Rule 'Azure.Deployment.AdminUsername' -Ref 'AZR-000284' -Type 'Microsoft.Resources/deployments' -Tag @{ release = 'GA'; ruleSet = '2022_09'; 'Azure.WAF/pillar' = 'Security'; } {
    RecurseDeploymentSensitive -Deployment $TargetObject
}

# Synopsis: Use secure parameters for setting properties of resources that contain sensitive information.
Rule 'Azure.Deployment.SecureValue' -Ref 'AZR-000316' -Type 'Microsoft.Resources/deployments' -Tag @{ release = 'GA'; ruleSet = '2022_12'; 'Azure.WAF/pillar' = 'Security'; } {
    RecurseSecureValue -Deployment $TargetObject
}

#endregion Rules

#region Helpers

function global:RecurseDeploymentSensitive {
    param (
        [Parameter(Mandatory = $True)]
        [PSObject]$Deployment
    )
    process {
        $propertyNames = $Configuration.GetStringValues('AZURE_DEPLOYMENT_SENSITIVE_PROPERTY_NAMES');
        $resources = @($Deployment.properties.template.resources);
        if ($resources.Length -eq 0) {
            return $Assert.Pass();
        }

        foreach ($resource in $resources) {
            if ($resource.type -eq 'Microsoft.Resources/deployments') {
                RecurseDeploymentSensitive -Deployment $resource;
            }
            else {
                foreach ($propertyName in $propertyNames) {
                    $found = $PSRule.GetPath($resource, "$..$propertyName");
                    if ($Null -eq $found -or $found.Length -eq 0) {
                        $Assert.Pass();
                    }
                    else {
                        Write-Debug "Found property name: $propertyName";
                        foreach ($value in $found) {
                            $Assert.Create(![PSRule.Rules.Azure.Runtime.Helper]::HasLiteralValue($value), $LocalizedData.LiteralSensitiveProperty, $propertyName);
                        }
                    }
                }
            }
        }
    }
}

function global:CheckPropertyUsesSecureParameter {
    param (
        [Parameter(Mandatory = $True)]
        [PSObject]$Resource,

        [Parameter(Mandatory = $True)]
        [AllowEmptyCollection()]
        [PSObject]$SecureParameters,

        [Parameter(Mandatory = $True)]
        [String]$PropertyPath
    )
    process {
        $propertiesInPath = $PropertyPath.Split(".")
        $propertyValue = $Resource
        foreach($aPropertyInThePath in $propertiesInPath) {
            $propertyValue = $propertyValue."$aPropertyInThePath"
        }

        if ($propertyValue) {
            $isSecure = [PSRule.Rules.Azure.Runtime.Helper]::HasSecureValue($propertyValue, $SecureParameters);
            $Assert.Create($isSecure).Reason($LocalizedData.SecureParameterRequired, $PropertyPath);
        }
        else {
            $Assert.Pass();
        }
    }
}

# Check resource properties that should be set by secure parameters.
function global:RecurseSecureValue {
    param (
        [Parameter(Mandatory = $True)]
        [PSObject]$Deployment
    )
    process {
        $resources = @($Deployment.properties.template.resources);
        if ($resources.Length -eq 0) {
            return $Assert.Pass();
        }

        $secureParameters = @($Deployment.properties.template.parameters.PSObject.properties | Where-Object {
            $_.Value.type -eq 'secureString' -or $_.Value.type -eq 'secureObject'
        } | ForEach-Object {
            $_.Name
        });
        Write-Debug -Message "Secure parameters are: $($secureParameters -join ', ')";

        foreach ($resource in $resources) {
            switch ($resource.type)
            {
                'Microsoft.Resources/Deployments' { 
                    RecurseSecureValue -Deployment $resource;
                }
                'Microsoft.AAD/DomainServices' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath 'properties.ldapsSettings.pfxCertificatePassword'
                }
                'Microsoft.ApiManagement/Service' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath 'properties.hostnameConfigurations.certificatePassword'
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath 'properties.certificates.certificatePassword'
                }
                'Microsoft.ApiManagement/Service/AuthorizationServers' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath 'properties.clientSecret'
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath 'properties.resourceOwnerPassword'
                }
                'Microsoft.ApiManagement/Service/Backends' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.proxy.password"
                }
                'Microsoft.ApiManagement/Service/Certificates' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.password"
                }
                'Microsoft.ApiManagement/Service/IdentityProviders' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.clientSecret"
                }
                'Microsoft.ApiManagement/Service/OpenidConnectProviders' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.clientSecret"
                }
                'Microsoft.ApiManagement/Service/Users' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.password"
                }
                'Microsoft.Automation/AutomationAccounts/Credentials' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.password"
                }
                'Microsoft.Batch/BatchAccounts/Pools' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.userAccounts.linuxUserConfiguration.sshPrivateKey"
                }
                'Microsoft.Blockchain/BlockchainMembers' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.password"
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.consortiumManagementAccountPassword"
                }
                'Microsoft.Blockchain/BlockchainMembers/TransactionNodes' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.password"
                }
                'Microsoft.BotService/BotServices/Connections' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.clientSecret"
                }
                'Microsoft.Compute/VirtualMachineScaleSets' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath 'properties.virtualMachineProfile.osProfile.adminPassword'
                }
                'Microsoft.Compute/VirtualMachineScaleSets/Virtualmachines' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.osProfile.adminPassword"
                }
                'Microsoft.Compute/VirtualMachines' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath 'properties.osProfile.adminPassword'
                }
                'Microsoft.ContainerInstance/ContainerGroups' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.imageRegistryCredentials.password"
                }
                'Microsoft.ContainerService/ContainerServices' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.servicePrincipalProfile.secret"
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.windowsProfile.adminPassword"
                }
                'Microsoft.ContainerService/ManagedClusters' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath 'properties.windowsProfile.adminPassword'
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath 'properties.servicePrincipalProfile.secret'
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath 'properties.aadProfile.serverAppSecret'
                }
                'Microsoft.ContainerService/OpenShiftManagedClusters' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath 'properties.authProfile.identityProviders.provider.secret'
                }
                'Microsoft.DBforMariaDB/Servers' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.administratorLoginPassword"
                }
                'Microsoft.DBforMySQL/Servers' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.administratorLoginPassword"
                }
                'Microsoft.DBforPostgreSQL/Servers' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.administratorLoginPassword"
                }
                'Microsoft.DataMigration/Services/Projects' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.sourceConnectionInfo.password"
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.targetConnectionInfo.password"
                }
                'Microsoft.DevTestLab/Labs/Formulas' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.formulaContent.properties.password"
                }
                'Microsoft.DevTestLab/Labs/Users/Secrets' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.value"
                }
                'Microsoft.DevTestLab/Labs/Virtualmachines' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.password"
                }
                'Microsoft.HDInsight/Clusters' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.securityProfile.domainUserPassword"
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.computeProfile.roles.osProfile.linuxOperatingSystemProfile.password"
                }
                'Microsoft.HDInsight/Clusters/Applications' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.computeProfile.roles.osProfile.linuxOperatingSystemProfile.password"
                }
                'Microsoft.KeyVault/Vaults/Secrets' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath 'properties.value'
                }
                'Microsoft.Logic/IntegrationAccounts/Agreements' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.content.x12.receiveAgreement.protocolSettings.securitySettings.passwordValue"
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.content.x12.sendAgreement.protocolSettings.securitySettings.passwordValue"
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.content.edifact.receiveAgreement.protocolSettings.envelopeSettings.recipientReferencePasswordValue"
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.content.edifact.sendAgreement.protocolSettings.envelopeSettings.recipientReferencePasswordValue"
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.content.edifact.receiveAgreement.protocolSettings.envelopeSettings.groupApplicationPassword"
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.content.edifact.sendAgreement.protocolSettings.envelopeSettings.groupApplicationPassword"
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.content.edifact.receiveAgreement.protocolSettings.envelopeOverrides.applicationPassword"
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.content.edifact.sendAgreement.protocolSettings.envelopeOverrides.applicationPassword"
                }
                'Microsoft.NetApp/NetAppAccounts' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.activeDirectories.password"
                }
                'Microsoft.Network/ApplicationGateways' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.sslCertificates.properties.password"
                }
                'Microsoft.Network/Connections' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.virtualNetworkGateway1.properties.vpnClientConfiguration.radiusServerSecret"
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.virtualNetworkGateway2.properties.vpnClientConfiguration.radiusServerSecret"
                }
                'Microsoft.Network/VirtualNetworkGateways' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.vpnClientConfiguration.radiusServerSecret"
                }
                'Microsoft.Network/VirtualWans/P2sVpnServerConfigurations' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.radiusServerSecret"
                }
                'Microsoft.Network/VpnServerConfigurations' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.radiusServerSecret"
                }
                'Microsoft.NotificationHubs/Namespaces/NotificationHubs' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.wnsCredential.properties.secretKey"
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.admCredential.properties.clientSecret"
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.baiduCredential.properties.baiduSecretKey"
                }
                'Microsoft.ServiceFabricMesh/Applications' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.services.properties.codePackages.imageRegistryCredential.password"
                }
                'Microsoft.ServiceFabricMesh/Secrets/Values' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.value"
                }
                'Microsoft.Sql/ManagedInstances' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.administratorLoginPassword"
                }
                'Microsoft.Sql/Servers' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.administratorLoginPassword"
                }
                'Microsoft.Sql/Servers/Databases/Extensions' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.administratorLoginPassword"
                }
                'Microsoft.Sql/Servers/Databases/SyncGroups' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.hubDatabasePassword"
                }
                'Microsoft.Sql/Servers/Databases/SyncGroups/SyncMembers' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.password"
                }
                'Microsoft.Sql/Servers/JobAgents/Credentials' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.password"
                }
                'Microsoft.SqlVirtualMachine/SqlVirtualMachines' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.wsfcDomainCredentials.clusterBootstrapAccountPassword"
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.wsfcDomainCredentials.clusterOperatorAccountPassword"
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.wsfcDomainCredentials.sqlServiceAccountPassword"
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.autoBackupSettings.password"
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.keyVaultCredentialSettings.servicePrincipalSecret"
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.serverConfigurationsManagementSettings.sqlConnectivityUpdateSettings.sqlAuthUpdatePassword"
                }
                'Microsoft.StorSimple/Managers/Devices/VolumeContainers' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.encryptionKey.value"
                }
                'Microsoft.StorSimple/Managers/StorageAccountCredentials' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.accessKey.value"
                }
                'Microsoft.StreamAnalytics/Streamingjobs' {
                    $objectsWithPasswords = $resource.properties.inputs + $resource.properties.outputs

                    foreach ($objectWithPassword in $objectsWithPasswords) {
                        CheckPropertyUsesSecureParameter -Resource $objectWithPassword -SecureParameters $secureParameters -PropertyPath "properties.datasource.properties.password"
                    }
                }
                'Microsoft.StreamAnalytics/Streamingjobs/Outputs' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.datasource.properties.password"
                }
                'Microsoft.Web/Certificates' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.password"
                }
                'Microsoft.Web/Sourcecontrols' {
                    CheckPropertyUsesSecureParameter -Resource $resource -SecureParameters $secureParameters -PropertyPath "properties.tokenSecret"
                }
                Default {
                    $Assert.Pass();
                }
            }
        }
    }
}

#endregion Helpers
# SIG # Begin signature block
# MIInrQYJKoZIhvcNAQcCoIInnjCCJ5oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCy6vEPgomLs/PE
# k3PFUYbBdl0Acb5CzHyl30pyjKuXc6CCDYEwggX/MIID56ADAgECAhMzAAACzI61
# lqa90clOAAAAAALMMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjIwNTEyMjA0NjAxWhcNMjMwNTExMjA0NjAxWjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQCiTbHs68bADvNud97NzcdP0zh0mRr4VpDv68KobjQFybVAuVgiINf9aG2zQtWK
# No6+2X2Ix65KGcBXuZyEi0oBUAAGnIe5O5q/Y0Ij0WwDyMWaVad2Te4r1Eic3HWH
# UfiiNjF0ETHKg3qa7DCyUqwsR9q5SaXuHlYCwM+m59Nl3jKnYnKLLfzhl13wImV9
# DF8N76ANkRyK6BYoc9I6hHF2MCTQYWbQ4fXgzKhgzj4zeabWgfu+ZJCiFLkogvc0
# RVb0x3DtyxMbl/3e45Eu+sn/x6EVwbJZVvtQYcmdGF1yAYht+JnNmWwAxL8MgHMz
# xEcoY1Q1JtstiY3+u3ulGMvhAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUiLhHjTKWzIqVIp+sM2rOHH11rfQw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDcwNTI5MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAeA8D
# sOAHS53MTIHYu8bbXrO6yQtRD6JfyMWeXaLu3Nc8PDnFc1efYq/F3MGx/aiwNbcs
# J2MU7BKNWTP5JQVBA2GNIeR3mScXqnOsv1XqXPvZeISDVWLaBQzceItdIwgo6B13
# vxlkkSYMvB0Dr3Yw7/W9U4Wk5K/RDOnIGvmKqKi3AwyxlV1mpefy729FKaWT7edB
# d3I4+hldMY8sdfDPjWRtJzjMjXZs41OUOwtHccPazjjC7KndzvZHx/0VWL8n0NT/
# 404vftnXKifMZkS4p2sB3oK+6kCcsyWsgS/3eYGw1Fe4MOnin1RhgrW1rHPODJTG
# AUOmW4wc3Q6KKr2zve7sMDZe9tfylonPwhk971rX8qGw6LkrGFv31IJeJSe/aUbG
# dUDPkbrABbVvPElgoj5eP3REqx5jdfkQw7tOdWkhn0jDUh2uQen9Atj3RkJyHuR0
# GUsJVMWFJdkIO/gFwzoOGlHNsmxvpANV86/1qgb1oZXdrURpzJp53MsDaBY/pxOc
# J0Cvg6uWs3kQWgKk5aBzvsX95BzdItHTpVMtVPW4q41XEvbFmUP1n6oL5rdNdrTM
# j/HXMRk1KCksax1Vxo3qv+13cCsZAaQNaIAvt5LvkshZkDZIP//0Hnq7NnWeYR3z
# 4oFiw9N2n3bb9baQWuWPswG0Dq9YT9kb+Cs4qIIwggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIZgjCCGX4CAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAsyOtZamvdHJTgAAAAACzDAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgS0MRdSNM
# U618AqeVXSLZEmWSdL7teRip6THC2vMzqE0wQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQCM+o1+3p6IKy3Xc/U9rvK47YfEbf13rfWBznlwWXLy
# +dflgp2UfGmRrqMrcpE94FJ9FY4gzmiYjYkvc7POdn9nYZVNnViAKqHlw+MFFyAQ
# cqGj9LJP7V++tVDog1UcNp3o2CpFKVLJ5hdHdhb4L5e1eFgrRMUXLEP1BnwyhytC
# lgJQGBp628gO0WU/QiFn+FYaCLzPc9ZjDPDE0mQpMSEN3n1ePBe7v0JCy1/TNHVm
# Q3xgOu9Rm8Bsupv0nPdsHxsq6901xHxBGdoQDjEzT40miN4rAwcUiteOr0tOlum6
# mxl7n1a9msl33qGVL2wW1WHV/GAseRlb+4m/SCQB+rHNoYIXDDCCFwgGCisGAQQB
# gjcDAwExghb4MIIW9AYJKoZIhvcNAQcCoIIW5TCCFuECAQMxDzANBglghkgBZQME
# AgEFADCCAVUGCyqGSIb3DQEJEAEEoIIBRASCAUAwggE8AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIOVf25QMNG2eVmzms+2kRKxhKa3Rxc09VVxtkPHS
# nqdzAgZjYr4oB7AYEzIwMjIxMTA5MTgwNzU2LjMwMVowBIACAfSggdSkgdEwgc4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1p
# Y3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMg
# VFNTIEVTTjo3ODgwLUUzOTAtODAxNDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgU2VydmljZaCCEV8wggcQMIIE+KADAgECAhMzAAABqFXwYanMMBhcAAEA
# AAGoMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# MB4XDTIyMDMwMjE4NTEyM1oXDTIzMDUxMTE4NTEyM1owgc4xCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVy
# YXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo3ODgw
# LUUzOTAtODAxNDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vydmlj
# ZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKPabcrALiXX8pjyXpcM
# N89KTvcmlAiDw4pU+HejZhibUeo/HUy+P9VxWhCX7ogeeKPJ677+LeVdPdG5hTvG
# DgSuo3w+AcmzcXZ2QCGUgUReLUKbmrr06bB0xhvtZwoelhxtPkjJFsbTGtSt+V7E
# 4VCjPdYqQZ/iN0ArXXmgbEfVyCwS+h2uooBhM5UcbPogtr5VpgdzbUM4/rWupmFV
# jPB1asn3+wv7aBCK8j9QUJroY4y1pmZSf0SuGMWY7cm2cvrbdm7XldljqRdHW+CQ
# AB4EqiOqgumfR+aSpo5T75KG0+nsBkjlGSsU1Bi15p4rP88pZnSop73Gem9GWO2G
# RLwP15YEnKsczxhGY+Z8NEa0QwMMiVlksdPU7J5qK9gxAQjOJzqISJzhIwQWtELq
# gJoHwkqTxem3grY7B7DOzQTnQpKWoL0HWR9KqIvaC7i9XlPv+ue89j9e7fmB4nh1
# hulzEJzX6RMU9THJMlbO6OrP3NNEKJW8jipCny8H1fuvSuFfuB7t++KK9g2c2NKu
# 5EzSs1nKNqtl4KO3UzyXLWvTRDO4D5PVQOda0tqjS/AWoUrxKC5ZPlkLE+YPsS5G
# +E/VCgCaghPyBZsHNK7wHlSf/26uhLnKp6XRAIroiEYl/5yW0mShjvnARPr0GIlS
# m0KrqSwCjR5ckWT1sKaEb8w3AgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQUNsfb4+L4
# UutlNh/MxjGkj0kLItUwHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIw
# XwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9w
# cy9jcmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3Js
# MGwGCCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENB
# JTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcD
# CDANBgkqhkiG9w0BAQsFAAOCAgEAcTuCS2Rqqmf2mPr6OUydhmUx+m6vpEPszWio
# JXbnsRbny62nF9YXTKuSNWH1QFfyc/2N3YTEp4hE8YthYKgDM/HUhUREX3WTwGse
# YuuDeSxWRJWCorAHF1kwQzIKgrUc3G+uVwAmG/EI1ELRExA4ftx0Ehrf59aJm7On
# gn0lTSSiKUeuGA+My6oCi/V8ETxz+eblvQANaltJgGfppuWXYT4jisQKETvoJjBv
# 5x+BA0oEFu7gGaeMDkZjnO5vdf6HeKneILs9ZvwIWkgYQi2ZeozbxglG5YwExoix
# ekxrRTDZwMokIYxXmccscQ0xXmh+I3vo7hV9ZMKTa9Paz5ne4cc8Odw1T+624mB0
# WaW9HAE1hojB6CbfundtV/jwxmdKh15plJXnN1yM7OL924HqAiJisHanpOEJ4Um9
# b3hFUXE2uEJL9aYuIgksVYIq1P29rR4X7lz3uEJH6COkoE6+UcauN6JYFghN9I8J
# RBWAhHX4GQHlngsdftWLLiDZMynlgRCZzkYI24N9cx+D367YwclqNY6CZuAgzwy1
# 2uRYFQasYHYK1hpzyTtuI/A2B8cG+HM6X1jf2d9uARwH6+hLkPtt3/5NBlLXpOl5
# iZyRlBi7iDXkWNa3juGfLAJ3ISDyNh7yu+H4yQYyRs/MVrCkWUJs9EivLKsNJ2B/
# IjNrStYwggdxMIIFWaADAgECAhMzAAAAFcXna54Cm0mZAAAAAAAVMA0GCSqGSIb3
# DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIw
# MAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAx
# MDAeFw0yMTA5MzAxODIyMjVaFw0zMDA5MzAxODMyMjVaMHwxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1l
# LVN0YW1wIFBDQSAyMDEwMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
# 5OGmTOe0ciELeaLL1yR5vQ7VgtP97pwHB9KpbE51yMo1V/YBf2xK4OK9uT4XYDP/
# XE/HZveVU3Fa4n5KWv64NmeFRiMMtY0Tz3cywBAY6GB9alKDRLemjkZrBxTzxXb1
# hlDcwUTIcVxRMTegCjhuje3XD9gmU3w5YQJ6xKr9cmmvHaus9ja+NSZk2pg7uhp7
# M62AW36MEBydUv626GIl3GoPz130/o5Tz9bshVZN7928jaTjkY+yOSxRnOlwaQ3K
# Ni1wjjHINSi947SHJMPgyY9+tVSP3PoFVZhtaDuaRr3tpK56KTesy+uDRedGbsoy
# 1cCGMFxPLOJiss254o2I5JasAUq7vnGpF1tnYN74kpEeHT39IM9zfUGaRnXNxF80
# 3RKJ1v2lIH1+/NmeRd+2ci/bfV+AutuqfjbsNkz2K26oElHovwUDo9Fzpk03dJQc
# NIIP8BDyt0cY7afomXw/TNuvXsLz1dhzPUNOwTM5TI4CvEJoLhDqhFFG4tG9ahha
# YQFzymeiXtcodgLiMxhy16cg8ML6EgrXY28MyTZki1ugpoMhXV8wdJGUlNi5UPkL
# iWHzNgY1GIRH29wb0f2y1BzFa/ZcUlFdEtsluq9QBXpsxREdcu+N+VLEhReTwDwV
# 2xo3xwgVGD94q0W29R6HXtqPnhZyacaue7e3PmriLq0CAwEAAaOCAd0wggHZMBIG
# CSsGAQQBgjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYEFCqnUv5kxJq+gpE8RjUp
# zxD/LwTuMB0GA1UdDgQWBBSfpxVdAF5iXYP05dJlpxtTNRnpcjBcBgNVHSAEVTBT
# MFEGDCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jv
# c29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wEwYDVR0lBAwwCgYI
# KwYBBQUHAwgwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGG
# MA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186a
# GMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3Br
# aS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsG
# AQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwDQYJKoZIhvcN
# AQELBQADggIBAJ1VffwqreEsH2cBMSRb4Z5yS/ypb+pcFLY+TkdkeLEGk5c9MTO1
# OdfCcTY/2mRsfNB1OW27DzHkwo/7bNGhlBgi7ulmZzpTTd2YurYeeNg2LpypglYA
# A7AFvonoaeC6Ce5732pvvinLbtg/SHUB2RjebYIM9W0jVOR4U3UkV7ndn/OOPcbz
# aN9l9qRWqveVtihVJ9AkvUCgvxm2EhIRXT0n4ECWOKz3+SmJw7wXsFSFQrP8DJ6L
# GYnn8AtqgcKBGUIZUnWKNsIdw2FzLixre24/LAl4FOmRsqlb30mjdAy87JGA0j3m
# Sj5mO0+7hvoyGtmW9I/2kQH2zsZ0/fZMcm8Qq3UwxTSwethQ/gpY3UA8x1RtnWN0
# SCyxTkctwRQEcb9k+SS+c23Kjgm9swFXSVRk2XPXfx5bRAGOWhmRaw2fpCjcZxko
# JLo4S5pu+yFUa2pFEUep8beuyOiJXk+d0tBMdrVXVAmxaQFEfnyhYWxz/gq77EFm
# PWn9y8FBSX5+k77L+DvktxW/tM4+pTFRhLy/AsGConsXHRWJjXD+57XQKBqJC482
# 2rpM+Zv/Cuk0+CQ1ZyvgDbjmjJnW4SLq8CdCPSWU5nR0W2rRnj7tfqAxM328y+l7
# vzhwRNGQ8cirOoo6CGJ/2XBjU02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYIC0jCC
# AjsCAQEwgfyhgdSkgdEwgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNv
# MSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo3ODgwLUUzOTAtODAxNDElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUA
# bLr8xJ9BB4rL4Yg58X1LZ5iQdyyggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFt
# cCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOcVzjowIhgPMjAyMjExMDkxMDU5
# MDZaGA8yMDIyMTExMDEwNTkwNlowdzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5xXO
# OgIBADAKAgEAAgIKngIB/zAHAgEAAgIR8zAKAgUA5xcfugIBADA2BgorBgEEAYRZ
# CgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0G
# CSqGSIb3DQEBBQUAA4GBAA6DcFKJA6VITtXEzUhaQmCnp0sse8cLl9UMgmcAAKv/
# nWTqt4uAuN/dKd3yGOmBGJ99sslw/g2C77pMtJg/upSfLC77fzJ2jF3g8Tb6i5/6
# Dqcl0oCM8KMywh8F0/zVrFc/h3SQw6JmX1FM3fJ0hW3av9/lp8K1w6o8Dcc7ljLK
# MYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMA
# AAGoVfBhqcwwGFwAAQAAAagwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJ
# AzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgMiOcOYgIFzvc82UzpAiD
# umY+GxuoONecV9T1KaQ7gIIwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCB0
# /ssdAMsHwnNwhfFBXPlFnRvWhHqSX9YLUxBDl1xlpjCBmDCBgKR+MHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABqFXwYanMMBhcAAEAAAGoMCIEIBtV
# vgRmvVCNfhhiXCzrSm0JQBAk+675oKmIgCOAL0IGMA0GCSqGSIb3DQEBCwUABIIC
# AG/Hc4YWsF2Z80BGbql+im9f6hmcXMW2oBMvKGizFzF33dchYEvMtNDvF/uKobxq
# Z4cVshgQiWY+vabPr6wbUXns3yGVApGsgi+lNQnEzZ3ytM9F08xgeAQkogkNczIl
# Xatf0orCjUcQT49cCT4479Si5OLyUZIYpS8znevhvYjo+TtjI/ZoLEBmgWQtnUlK
# 14RvYTXR2ccNAnrmDpL1iyULGtAg99RzDUEDH/g0UH573hKcOSucXWrS1iiIlKpI
# IhY1Kf0dyTjBs5VtETL8BHf5C0l6k+vmVdev9KnS2oOfuI9S0ASOaKwcwj+sE+43
# fF7d23mN+XwbZPuBRCp4oYPuDgEAXPyvI601xjhHXkQ6rdSi6BX5cbWm3nRtv4c0
# SvalC0wqHCRHTDQD6ZuvSKqy0mvf//fO4gJmfYopAKBL7ejhkdJprr2U8SdInxnf
# 3bwdmCFuWG5wwA7QBhzz8tIuqSwJ8Umb7Hu1wO8uwi+io7uoh9HrOnEQJDTDLGip
# e+CDxJH68ZuZSOSskKT8RmLB/c/IgX/0JjtPllwykOuXE4klTyYOv2e4UYFe8ZA1
# wZ9b0/nOQZsaxlgAQzLWs/GId4ilHN/BQ5VDa9eGyv3ZtKmBk8gmCCBHV2IMu/pu
# Nb7zayqxQzs/V3orE6MYESVvzB/WsA94zjiq+aAq8MCd
# SIG # End signature block
