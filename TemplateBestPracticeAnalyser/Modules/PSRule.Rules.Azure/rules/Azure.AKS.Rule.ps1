# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#
# Validation rules for Azure Kubernetes Service (AKS)
#

# Synopsis: AKS control plane and nodes pools should use a current stable release.
Rule 'Azure.AKS.Version' -Ref 'AZR-000015' -Type 'Microsoft.ContainerService/managedClusters', 'Microsoft.ContainerService/managedClusters/agentPools' -Tag @{ release = 'GA'; ruleSet = '2020_06'; 'Azure.WAF/pillar' = 'Security'; } -Labels @{ 'Azure.ASB.v3/control' = 'PV-7' } {
    $minVersion = $Configuration.GetValueOrDefault('Azure_AKSMinimumVersion', $Configuration.AZURE_AKS_CLUSTER_MINIMUM_VERSION);
    if ($PSRule.TargetType -eq 'Microsoft.ContainerService/managedClusters') {
        $Assert.Version($TargetObject, 'Properties.kubernetesVersion', ">=$minVersion");
    }
    elseif ($PSRule.TargetType -eq 'Microsoft.ContainerService/managedClusters/agentPools') {
        if (!$Assert.HasField($TargetObject, 'Properties.orchestratorVersion').Result) {
            $Assert.Pass();
        }
        else {
            $Assert.Version($TargetObject, 'Properties.orchestratorVersion', ">=$minVersion");
        }
    }
}

# Synopsis: AKS agent pools should run the same Kubernetes version as the cluster
Rule 'Azure.AKS.PoolVersion' -Ref 'AZR-000016' -Type 'Microsoft.ContainerService/managedClusters' -Tag @{ release = 'GA'; ruleSet = '2020_06' } {
    $clusterVersion = $TargetObject.Properties.kubernetesVersion;
    $agentPools = @(GetAgentPoolProfiles);
    if ($agentPools.Length -eq 0) {
        return $Assert.Pass();
    }
    foreach ($agentPool in $agentPools) {
        $Assert.HasDefaultValue($agentPool, 'orchestratorVersion', $clusterVersion).
            Reason($LocalizedData.AKSNodePoolVersion, $agentPool.name, $agentPool.orchestratorVersion);
    }
}

# Synopsis: AKS node pools should use scale sets
Rule 'Azure.AKS.PoolScaleSet' -Ref 'AZR-000017' -Type 'Microsoft.ContainerService/managedClusters', 'Microsoft.ContainerService/managedClusters/agentPools' -Tag @{ release = 'GA'; ruleSet = '2020_06' } {
    $agentPools = @(GetAgentPoolProfiles);
    if ($agentPools.Length -eq 0) {
        return $Assert.Pass();
    }
    foreach ($agentPool in $agentPools) {
        $Assert.HasFieldValue($agentPool, 'type', 'VirtualMachineScaleSets').
            Reason($LocalizedData.AKSNodePoolType, $agentPool.name);
    }
}

# Synopsis: AKS nodes should use a minimum number of pods
Rule 'Azure.AKS.NodeMinPods' -Ref 'AZR-000018' -Type 'Microsoft.ContainerService/managedClusters', 'Microsoft.ContainerService/managedClusters/agentPools' -Tag @{ release = 'GA'; ruleSet = '2020_06' } {
    $agentPools = @(GetAgentPoolProfiles);
    if ($agentPools.Length -eq 0) {
        return $Assert.Pass();
    }
    foreach ($agentPool in $agentPools) {
        $Assert.GreaterOrEqual($agentPool, 'maxPods', $Configuration.Azure_AKSNodeMinimumMaxPods);
    }
} -Configure @{ Azure_AKSNodeMinimumMaxPods = 50 }

# Synopsis: Use Autoscaling to ensure AKS cluster is running efficiently with the right number of nodes for the workloads present.
Rule 'Azure.AKS.AutoScaling' -Ref 'AZR-000019' -Type 'Microsoft.ContainerService/managedClusters', 'Microsoft.ContainerService/managedClusters/agentPools' -Tag @{ release = 'GA'; ruleSet = '2021_09'; } {
    $agentPools = @(GetAgentPoolProfiles);

    if ($agentPools.Length -eq 0) {
        return $Assert.Pass();
    }

    foreach ($agentPool in $agentPools) {

        # Autoscaling only available on virtual machine scale sets
        if ($Assert.HasFieldValue($agentPool, 'type', 'VirtualMachineScaleSets').Result) {
            $Assert.HasFieldValue($agentPool, 'enableAutoScaling', $True).Reason($LocalizedData.AKSAutoScaling, $agentPool.name);
        }
        else {
            $Assert.Pass()
        }
    }
}

# Synopsis: AKS clusters using Azure CNI should use large subnets to reduce IP exhaustion issues.
Rule 'Azure.AKS.CNISubnetSize' -Ref 'AZR-000020' -If { IsExport } -With 'Azure.AKS.AzureCNI' -Tag @{ release = 'GA'; ruleSet = '2021_09'; } {
    $clusterSubnets = @(GetSubResources -ResourceType 'Microsoft.Network/virtualNetworks/subnets');

    if ($clusterSubnets.Length -eq 0) {
        return $Assert.Pass();
    }

    $configurationMinimumSubnetSize = $Configuration.AZURE_AKS_CNI_MINIMUM_CLUSTER_SUBNET_SIZE;

    foreach ($subnet in $clusterSubnets) {
        $subnetAddressPrefixSize = [int]$subnet.Properties.addressPrefix.Split('/')[-1];
        
        $Assert.LessOrEqual($subnetAddressPrefixSize, '.', $configurationMinimumSubnetSize).
            Reason(
                $LocalizedData.AKSAzureCNI, 
                $subnet.Name, 
                $configurationMinimumSubnetSize
            );
    }
} -Configure @{ AZURE_AKS_CNI_MINIMUM_CLUSTER_SUBNET_SIZE = 23 }

# Synopsis: AKS clusters deployed with virtual machine scale sets should use availability zones in supported regions for high availability.
Rule 'Azure.AKS.AvailabilityZone' -Ref 'AZR-000021' -Type 'Microsoft.ContainerService/managedClusters' -Tag @{ release = 'GA'; ruleSet = '2021_09'; } {
    $agentPools = @(GetAgentPoolProfiles);

    if ($agentPools.Length -eq 0) {
        return $Assert.Pass();
    }

    $virtualMachineScaleSetProvider = [PSRule.Rules.Azure.Runtime.Helper]::GetResourceType('Microsoft.Compute', 'virtualMachineScaleSets');

    $configurationZoneMappings = $Configuration.AZURE_AKS_ADDITIONAL_REGION_AVAILABILITY_ZONE_LIST;
    $providerZoneMappings = $virtualMachineScaleSetProvider.ZoneMappings;
    $mergedAvailabilityZones = PrependConfigurationZoneWithProviderZone -ConfigurationZone $configurationZoneMappings -ProviderZone $providerZoneMappings;

    $availabilityZones = GetAvailabilityZone -Location $TargetObject.Location -Zone $mergedAvailabilityZones;

    if (-not $availabilityZones) {
        return $Assert.Pass();
    }

    $joinedZoneString = $availabilityZones -join ', ';

    foreach ($agentPool in $agentPools) {

        # Availability zones only available on virtual machine scale sets
        if ($Assert.HasFieldValue($agentPool, 'type', 'VirtualMachineScaleSets').Result) {
            $Assert.HasFieldValue($agentPool, 'availabilityZones').
                Reason($LocalizedData.AKSAvailabilityZone, $agentPool.name, $TargetObject.Location, $joinedZoneString);
        }
        else {
            $Assert.Pass();
        }
    }
} -Configure @{ AZURE_AKS_ADDITIONAL_REGION_AVAILABILITY_ZONE_LIST = @() }

# Synopsis: AKS clusters should collect security-based audit logs to assess and monitor the compliance status of workloads.
Rule 'Azure.AKS.AuditLogs' -Ref 'AZR-000022' -Type 'Microsoft.ContainerService/managedClusters' -Tag @{ release = 'GA'; ruleSet = '2021_09'; 'Azure.WAF/pillar' = 'Security'; } -Labels @{ 'Azure.ASB.v3/control' = 'LT-4' } {
    $diagnosticLogs = @(GetSubResources -ResourceType 'Microsoft.Insights/diagnosticSettings', 'Microsoft.ContainerService/managedClusters/providers/diagnosticSettings');

    $Assert.Greater($diagnosticLogs, '.', 0).Reason($LocalizedData.DiagnosticSettingsNotConfigured, $TargetObject.name);

    foreach ($setting in $diagnosticLogs) {
        $kubeAuditEnabledLog = @($setting.Properties.logs | Where-Object {
            $_.category -in 'kube-audit', 'kube-audit-admin' -and $_.enabled
        });

        $guardEnabledLog = @($setting.Properties.logs | Where-Object {
            $_.category -eq 'guard' -and $_.enabled
        });

        $auditLogsEnabled = $Assert.Greater($kubeAuditEnabledLog, '.', 0).Result -and
                            $Assert.Greater($guardEnabledLog, '.', 0).Result;

        $Assert.Create($auditLogsEnabled, $LocalizedData.AKSAuditLogs, $setting.name);
    }
}

# Synopsis: AKS clusters should collect platform diagnostic logs to monitor the state of workloads.
Rule 'Azure.AKS.PlatformLogs' -Ref 'AZR-000023' -Type 'Microsoft.ContainerService/managedClusters' -Tag @{ release = 'GA'; ruleSet = '2021_09'; 'Azure.WAF/pillar' = 'Security'; } -Labels @{ 'Azure.ASB.v3/control' = 'LT-4' } {
    $configurationLogCategoriesList = $Configuration.GetStringValues('AZURE_AKS_ENABLED_PLATFORM_LOG_CATEGORIES_LIST');

    if ($configurationLogCategoriesList.Length -eq 0) {
        return $Assert.Pass();
    }

    $diagnosticLogs = @(GetSubResources -ResourceType 'Microsoft.Insights/diagnosticSettings', 'Microsoft.ContainerService/managedClusters/providers/diagnosticSettings');

    $Assert.Greater($diagnosticLogs, '.', 0).Reason($LocalizedData.DiagnosticSettingsNotConfigured, $TargetObject.name);

    $availableLogCategories = @{
        Logs = @(
            'cluster-autoscaler', 
            'kube-apiserver', 
            'kube-controller-manager', 
            'kube-scheduler'
        )
        Metrics = @(
            'AllMetrics'
        )
    }

    $configurationLogCategories = @($configurationLogCategoriesList | Where-Object {
        $_ -in $availableLogCategories.Logs
    });

    $configurationMetricCategories = @($configurationLogCategoriesList | Where-Object {
        $_ -in $availableLogCategories.Metrics
    });

    $logCategoriesNeeded = [System.Math]::Min(
        $configurationLogCategories.Length, 
        $availableLogCategories.Logs.Length
    );

    $metricCategoriesNeeded = [System.Math]::Min(
        $configurationMetricCategories.Length, 
        $availableLogCategories.Metrics.Length
    );

    $logCategoriesJoinedString = $configurationLogCategoriesList -join ', ';

    foreach ($setting in $diagnosticLogs) {
        $platformLogs = @($setting.Properties.logs | Where-Object {
            $_.enabled -and
            $_.category -in $configurationLogCategories -and
            $_.category -in $availableLogCategories.Logs
        });

        $metricLogs = @($setting.Properties.metrics | Where-Object {
            $_.enabled -and 
            $_.category -in $configurationMetricCategories -and
            $_.category -in $availableLogCategories.Metrics
        });

        $platformLogsEnabled = $Assert.HasFieldValue($platformLogs, 'Length', $logCategoriesNeeded).Result -and 
                               $Assert.HasFieldValue($metricLogs, 'Length', $metricCategoriesNeeded).Result

        $Assert.Create(
            $platformLogsEnabled, 
            $LocalizedData.AKSPlatformLogs, 
            $setting.name, 
            $logCategoriesJoinedString
        );
    }
} -Configure @{
    AZURE_AKS_ENABLED_PLATFORM_LOG_CATEGORIES_LIST = @(
        'cluster-autoscaler', 
        'kube-apiserver', 
        'kube-controller-manager', 
        'kube-scheduler',
        'AllMetrics'
    )
}

# Synopsis: AKS clusters should have Uptime SLA enabled to ensure availability of control plane components for production workloads.
Rule 'Azure.AKS.UptimeSLA' -Ref 'AZR-000285' -Type 'Microsoft.ContainerService/managedClusters' -Tag @{ release = 'GA'; ruleSet = '2022_09'; } {
    $Assert.Contains($TargetObject, 'sku.tier', 'Paid');
}

# Synopsis: AKS clusters should use ephemeral OS disks which can provide lower read/write latency, along with faster node scaling and cluster upgrades.
Rule 'Azure.AKS.EphemeralOSDisk' -Ref 'AZR-000287' -Level Warning -Type 'Microsoft.ContainerService/managedClusters', 'Microsoft.ContainerService/managedClusters/agentPools' -Tag @{ release = 'GA'; ruleSet = '2022_09' } {
    $agentPools = @(GetAgentPoolProfiles);
    if ($agentPools.Length -eq 0) {
        return $Assert.Pass();
    }
    foreach ($agentPool in $agentPools) {
        $Assert.HasDefaultValue($agentPool, 'osDiskType', 'Ephemeral').
        ReasonIf($agentPool.osDiskType, $LocalizedData.AKSEphemeralOSDiskNotConfigured);
    }
}

#region Helper functions

function global:GetAgentPoolProfiles {
    [CmdletBinding()]
    [OutputType([PSObject])]
    param ()
    process {
        if ($PSRule.TargetType -eq 'Microsoft.ContainerService/managedClusters') {
            $TargetObject.Properties.agentPoolProfiles;
            @(GetSubResources -ResourceType 'Microsoft.ContainerService/managedClusters/agentPools' | ForEach-Object {
                [PSCustomObject]@{
                    name = $_.name
                    type = $_.properties.type
                    maxPods = $_.properties.maxPods
                    orchestratorVersion = $_.properties.orchestratorVersion
                    enableAutoScaling = $_.properties.enableAutoScaling
                    availabilityZones = $_.properties.availabilityZones
                    osDiskType = $_.properties.osDiskType
                }
            });
        }
        elseif ($PSRule.TargetType -eq 'Microsoft.ContainerService/managedClusters/agentPools') {
            [PSCustomObject]@{
                name = $TargetObject.name
                type = $TargetObject.properties.type
                maxPods = $TargetObject.properties.maxPods
                orchestratorVersion = $TargetObject.properties.orchestratorVersion
                enableAutoScaling = $TargetObject.properties.enableAutoScaling
                availabilityZones = $TargetObject.properties.availabilityZones
                osDiskType = $TargetObject.properties.osDiskType
            }
        }
    }
}

#endregion Helper functions

# SIG # Begin signature block
# MIInoAYJKoZIhvcNAQcCoIInkTCCJ40CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB4Wij4gzQ+CNu+
# lqUGMZyFRNtntjY7TKDys69d+ZaEtqCCDYEwggX/MIID56ADAgECAhMzAAACzI61
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIZdTCCGXECAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAsyOtZamvdHJTgAAAAACzDAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgJjtu7yVc
# wufpbMJef3kNRx2EqRD7CwpwLX7lhs0NbZwwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQCSupXQMSJg2Pu3zdg+ZTMmWSEtYIEGPTzAID3iFoyR
# F7iVjHXkggyF6B4Zix7FA0DvVFKMmCbMtgmQQE5dcYsKksoqYIpCO5EZCdm4gUEI
# 1KMYwEhtw52nE0C0HLcF8cgisNmT5wWnpWjP9BPVYOiuEFe8SiwOFRhgvE8CGx88
# hPKbtO/XXiNekNDUg1I/e5oI9Z4lkqeloZkB/BihFQ9o+Cis3i5QRLohwCaOh7wM
# 4KFzh4YDky6feYdLKpG4qNveFPceedlKNPdlyGYJS6eqD9zI2njSbcqZD5W/F+0o
# EHvXovDB/0hdV391cbp2kZHvEmnu4OWwtvIQnGqR2QcQoYIW/zCCFvsGCisGAQQB
# gjcDAwExghbrMIIW5wYJKoZIhvcNAQcCoIIW2DCCFtQCAQMxDzANBglghkgBZQME
# AgEFADCCAVEGCyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIIudeL/+5UuMCj/ZfbwGaYdA5ODnZoG3rxU4kmMj
# jaNbAgZja9ADXmQYEzIwMjIxMTA5MTgwNzQ3LjUwMlowBIACAfSggdCkgc0wgcox
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1p
# Y3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOjdCRjEtRTNFQS1CODA4MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNloIIRVjCCBwwwggT0oAMCAQICEzMAAAHI+bDuZ+3qa0YAAQAAAcgw
# DQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcN
# MjIxMTA0MTkwMTM3WhcNMjQwMjAyMTkwMTM3WjCByjELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2Eg
# T3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046N0JGMS1FM0VBLUI4
# MDgxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0G
# CSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC5y51+KE+DJFbCeci4kKpzdMK0WTRc
# 6KYVwqNT1tLpYWeDaX4WsiJ3SY9nspazoTCPbVf5mQaQzrH6jMeWY22cdJDjymMg
# V2UpciiHt9KjjUDifS1AiXCGzy4hgihynvbHAMEcpJnEZoRr/TvTuLI7D5pdlc1x
# PGA2JEQBJv22GUtkzvmZ8kiAFW9SZ0tlz5c5RjDP/y6XsgTO080fhyfwKfS0mEgV
# +nad62vwZg2iLIirG54bv6xK3bFeXv+KBzlwc9mdaF+X09oHj5K62sDzMCHNUdOe
# PhF9/EDhHeTgFFs90ajBB85/3ll5jEtMd/lrAHSepnE5j7K4ZaF/qGnlEZGi5z1t
# 5Vm/3wzV6thrnlLVqFmAYNAnJxW0TLzZGWYp9Nhja42aU8ta2cPuwOWlWSFhAYq5
# Nae7BAqr1lNIT7RXZwfwlpYFglAwi5ZYzze8s+jchP9L/mNPahk5L2ewmDDALBFS
# 1i3C2rz88m2+3VXpWgbhZ3b8wCJ+AQk6QcXsBE+oj1e/bz6uKolnmaMsbPzh0/av
# Kh7SXFhLPc9PkSsqhLT7Mmlg0BzFu/ZReJOTdaP+Zne26XPrPhedKXmDLQ8t6v4R
# WPPgb3oZxmArZ30b65jKUdbAGd4i/1gVCPrIx1b/iwSmQRuumIk16ZzFQKYGKlnt
# Jzfmu/i62Qnj9QIDAQABo4IBNjCCATIwHQYDVR0OBBYEFLVcL0mButLAsNOIklPi
# Irs1S+T1MB8GA1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRY
# MFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01p
# Y3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEF
# BQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9w
# a2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAo
# MSkuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZI
# hvcNAQELBQADggIBAMPWclLIQ8OpKCd+QWJ8hu14lvs2RkJtGPnIEaJPV/19Ma9R
# vkJbuTd5Kne7FSqib0tbKRw19Br9h/DSWJsSKb1hGNQ1wvjaggWq2n/uuX2CDrWi
# IHw8H7q8sSaNeRjFRRHxaMooLlDl3H3oHbV9pJyjYw6a+NjEZRHsCf7jnb2VA88u
# psQpGNw1Bv6n6aRAfZd4xuyHkRAKRO5gCKYVOCe6LZk8UsS4GnEErnPYecqd4dQn
# 2LilwpZ0KoXUA5U3yBcgfRHQV+UxwKDlNby/3RXDH+Y/doTYiB7W4Twz1g0Gfnvv
# o/GYDXpn5zaz6Fgj72wlmGFEDxpJhpyuUvPtpT/no68RhERFBm224AWStX4z8n60
# J4Y2/QZ3vljiUosynn/TGg6+I8F0HasPkL9T4Hyq3VsGpAtVnXAdHLT/oeEnFs6L
# YiAYlo4JgsZfbPPRUBPqZnYFNasmZwrpIO/utfumyAL4J/W3RHVpYKQIcm2li7Iq
# N/tSh1FrN685/pXTVeSsBEcqsjttCgcUv6y6faWIkIGM3nWYNagSBQIS/AHeX5EV
# gAvRoiKxzlxNoZf9PwX6IBvP6PYYZW6bzmARBL24vNJ52hg/IRfFNuXB7AZ0DGoh
# loqjNEGjDj06cv7kKCihUx/dlKqnFzZALQTTeXpz+8KGRjKoxersvB3g+ceqMIIH
# cTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0BAQsFADCB
# iDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMp
# TWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEw
# OTMwMTgyMjI1WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOThpkzntHIh
# C3miy9ckeb0O1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xPx2b3lVNx
# WuJ+Slr+uDZnhUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ3MFEyHFc
# UTE3oAo4bo3t1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOtgFt+jBAc
# nVL+tuhiJdxqD89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYtcI4xyDUo
# veO0hyTD4MmPfrVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXAhjBcTyzi
# YrLNueKNiOSWrAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9
# fvzZnkXftnIv231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdH
# GO2n6Jl8P0zbr17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7X
# KHYC4jMYctenIPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiE
# R9vcG9H9stQcxWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/
# eKtFtvUeh17aj54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkrBgEEAYI3
# FQEEBQIDAQABMCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAd
# BgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEE
# AYI3TIN9AQEwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMI
# MBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMB
# Af8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1Ud
# HwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3By
# b2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQRO
# MEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2Vy
# dHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEBCwUAA4IC
# AQCdVX38Kq3hLB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnXwnE2P9pk
# bHzQdTltuw8x5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gng
# ugnue99qb74py27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jfZfakVqr3
# lbYoVSfQJL1AoL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHC
# gRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6
# MhrZlvSP9pEB9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEU
# BHG/ZPkkvnNtyo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6OEuabvsh
# VGtqRRFHqfG3rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+
# fpO+y/g75LcVv7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrp
# NPgkNWcr4A245oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784cETRkPHI
# qzqKOghif9lwY1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAs0wggI2AgEBMIH4
# oYHQpIHNMIHKMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUw
# IwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1U
# aGFsZXMgVFNTIEVTTjo3QkYxLUUzRUEtQjgwODElMCMGA1UEAxMcTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUA384TULvGNTQKUgNd
# AGK5wBjuy7KggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAN
# BgkqhkiG9w0BAQUFAAIFAOcWToEwIhgPMjAyMjExMTAwMDA2MjVaGA8yMDIyMTEx
# MTAwMDYyNVowdjA8BgorBgEEAYRZCgQBMS4wLDAKAgUA5xZOgQIBADAJAgEAAgFi
# AgH/MAcCAQACAhGPMAoCBQDnF6ABAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisG
# AQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQAD
# gYEABDGDSe5Iz7he/XTKZgHSe5iRH2WiboHuKPirzzXRkrHOh+tzcjX3hj5pYC13
# LPh88exY6SOZN8sBLrKvsp8r5DA41T0OACXZQHp1mHIb3tHkApf2rtPfUnDV3mKO
# q+hoJG5X4F61QRy8OZ0UMK9+pAN6tZ3vss6eyKkVNsjHkPsxggQNMIIECQIBATCB
# kzB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQD
# Ex1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAcj5sO5n7eprRgAB
# AAAByDANBglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJ
# EAEEMC8GCSqGSIb3DQEJBDEiBCDJObOQdWlryTxs7GgeKJrQJVnTMyDKSlzaR8Js
# XLagLjCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIGIAmM/NP22jL8cOo3Kk
# ry9BVuE3bwNPZ8R37D4bhANmMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# UENBIDIwMTACEzMAAAHI+bDuZ+3qa0YAAQAAAcgwIgQgxnBHgPZDyWesCX6Sypzp
# oVsj1tBB6sbTSVAG13KcKlUwDQYJKoZIhvcNAQELBQAEggIAlX7nf1PWZD5kSwZO
# zSzAZB8IGmelavQIWlu7Ar5LclzR+C5PVoeYnCmlMX6m0E+NDvR4XWGGVo0BoeVa
# yuORX74OxenkXmeLaDFtrsiG7IPNfbEiICwjEteQHwVLyJHWwqCrOThXmUDfh22l
# 2BD0kHSgTiwgRUk1dcQidfdNiQ0Ft6h9JwbK6US2qUBCHjTzUZuh/tQ+LWWAN0xi
# C3oPyHg2rZfnIrOJSmRMqKfGZTG82dyTcl8CAMLQU/TUNLoK8Jli43i6ZQp9Iq3k
# Rztwtkuzhg/ftsQ1Iq6IEgH4NpceYDjUckryPotIN4OJuZ0hs6LIak5WtDzFL3MP
# EtmO6nMSFm8wiRwxC/ax9NXMuR6HeNtp2he9WE49STMRp+IVbheBFh2TiJYMTF7l
# aE1Wk7fbHnOT3KGaO/2uvvwZ2tuNTlfbLe/7+w0vLv1ildr8H8B8L12SAo+6fuMW
# MpVUSe3qTbcZo7kIQrh4bkZoR5koSpkQLKSr9Q9j0CfWQLOTAYjxCxN0XsPAuFLj
# 1znzWlD2Dw17GAROH4rVZafA8GbfXIBcJmBHbuuC5xiHkwtDAZZtG2/aBWQEhG98
# 3pr2kOm2Tepkh0XLggxQMPWs3319+onPJkxr1ehffTs8nCGAhGxqVxFTlGurvmZQ
# 7WtJT1aOf8b4V81EaKiDTMcgPDs=
# SIG # End signature block
