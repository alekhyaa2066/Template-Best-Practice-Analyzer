# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#
# Helper functions for rules
#

# Add a custom function to filter by resource type
function global:ResourceType {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param (
        [Parameter(Mandatory = $True)]
        [String]$ResourceType
    )
    process {
        return $PSRule.TargetType -eq $ResourceType;
    }
}

function global:ExtensionResourceType {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param (
        [Parameter(Mandatory = $True)]
        [String]$ResourceType
    )
    process {
        return $TargetObject.ExtensionResourceType -eq $ResourceType;
    }
}

# Get sub resources of a specific resource type
function global:GetSubResources {
    [CmdletBinding()]
    [OutputType([PSObject[]])]
    param (
        [Parameter(Mandatory = $True)]
        [String[]]$ResourceType,

        [Parameter(Mandatory = $False)]
        [String[]]$Name
    )
    process {
        $results = @();
        $resources = @($TargetObject.resources);
        for ($i = 0; $i -lt $resources.Length; $i++) {
            $path = "resources[$i]";
            if (($resources[$i].ResourceType -in $ResourceType -or $resources[$i].Type -in $ResourceType -or $resources[$i].ExtensionResourceType -in $ResourceType) -and
                ($Null -eq $Name -or $Name.Length -eq 0 -or [PSRule.Rules.Azure.Runtime.Helper]::GetSubResourceName($resources[$i].Name) -in $Name -or [PSRule.Rules.Azure.Runtime.Helper]::GetSubResourceName($resources[$i].ResourceName) -in $Name)) {
                $resource = $resources[$i];
                if (!([bool]$resource.PSObject.Members['_PSRule'])) {
                    $Null = Add-Member -InputObject $resource -MemberType NoteProperty -Name '_PSRule' -Value @{
                        path = $path;
                    }
                }
                elseif (!([bool]$resource._PSRule.PSObject.Members['path'])) {
                    $Null = Add-Member -InputObject $resource._PSRule -MemberType NoteProperty -Force -Name 'path' -Value $path;
                }
                $results += $resource;
            }
        }
        return $results;
    }
}

# Certain rules only apply if resource data has been exported
function global:IsExport {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param ()
    process {
        return $Null -ne $TargetObject.SubscriptionId;
    }
}

function global:HasPeerNetwork {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param ()
    process {
        if ($PSRule.TargetType -ne 'Microsoft.Network/virtualNetworks') {
            return $False;
        }
        $peers = $TargetObject.Properties.virtualNetworkPeerings;
        if ($Null -eq $peers) {
            return $False;
        }
        $item = @($peers);
        return $item.Length -gt 0;
    }
}

function global:SupportsAcceleratedNetworking {
    [CmdletBinding()]
    param ()
    process {
        if ($PSRule.TargetType -ne 'Microsoft.Compute/virtualMachines' -or !(IsExport)) {
            return $False;
        }
        if ($Null -eq ($TargetObject.Resources | Where-Object { $_.ResourceType -eq 'Microsoft.Network/networkInterfaces' })) {
            return $False;
        }

        $vmSize = $TargetObject.Properties.hardwareProfile.vmSize;
        if ($vmSize -notLike 'Standard_*_*') {
            if ($vmSize -match '^Standard_(F|B[1-2][0-9]ms)') {
                return $True;
            }
            else {
                return $False;
            }
        }

        $vmSizeParts = $vmSize.Split('_');
        if ($Null -eq $vmSizeParts) {
            return $False;
        }

        $generation = $vmSizeParts[2];
        $size = $vmSizeParts[1];

        # Generation v2
        if ($generation -eq 'v2') {
            if ($size -notMatch '^(A|NC|DS1$|D1$|F[1-2]s)') {
                return $True;
            }
        }
        # Generation v3
        elseif ($generation -eq 'v3') {
            if ($size -notMatch '^(E2s?|E[2-8]-2|D2s?|NC)') {
                return $True;
            }
        }
        return $False;
    }
}

function global:IsWindowsOS {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param ()
    process {
        if ($PSRule.TargetType -notIn 'Microsoft.Compute/virtualMachines', 'Microsoft.Compute/virtualMachineScaleSets') {
            return $False;
        }
        return ($TargetObject.Properties.storageProfile.osDisk.osType -eq 'Windows') -or
            ($TargetObject.Properties.storageProfile.imageReference.publisher -in 'MicrosoftSQLServer', 'MicrosoftWindowsServer', 'MicrosoftVisualStudio', 'MicrosoftWindowsDesktop') -or
            ($TargetObject.Properties.virtualMachineProfile.storageProfile.osDisk.osType -eq 'Windows') -or
            ($TargetObject.Properties.virtualMachineProfile.storageProfile.imageReference.publisher -in 'MicrosoftSQLServer', 'MicrosoftWindowsServer', 'MicrosoftVisualStudio', 'MicrosoftWindowsDesktop')
    }
}

function global:IsWindowsClientOS {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param ()
    process {
        if ($PSRule.TargetType -notIn 'Microsoft.Compute/virtualMachines', 'Microsoft.Compute/virtualMachineScaleSets') {
            return $False;
        }
        return $TargetObject.Properties.storageProfile.imageReference.publisher -eq 'MicrosoftWindowsDesktop';
    }
}

function global:SupportsHybridUse {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param ()
    process {
        if ($PSRule.TargetType -ne 'Microsoft.Compute/virtualMachines') {
            return $False;
        }
        return (
            ($TargetObject.Properties.storageProfile.osDisk.osType -eq 'Windows') -or
            ($TargetObject.Properties.storageProfile.imageReference.publisher -in 'MicrosoftSQLServer', 'MicrosoftWindowsServer')
        ) -and !(IsWindowsClientOS);
    }
}

function global:IsLinuxOffering {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param ($imageReference)
    process {
        $configLinuxOffers = $Configuration.GetStringValues('AZURE_LINUX_OS_OFFERS');
        foreach ($configLinuxOffer in $configLinuxOffers) {
            if ($configLinuxOffer -ieq $imageReference.offer) {
                return $True
            }
        }

        $someLinuxOSNames = @('ubuntu', 'linux', 'rhel', 'centos', 'redhat', 'debian', 'suse')
        foreach ($linuxOSName in $someLinuxOSNames) {
            if ($imageReference.offer -match $linuxOSName) {
                return $True
            }
        }
        
        foreach ($publicLinuxOffering in $PublicLinuxOfferings) {
            if ($publicLinuxOffering[0] -ieq $imageReference.publisher -and $publicLinuxOffering[1] -ieq $imageReference.offer) {
                return $True
            }
        }

        return $False
    }
}
 
function global:VMHasLinuxOS {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param ()
    process {
        if ($PSRule.TargetType -ne 'Microsoft.Compute/virtualMachines') {
            return $False;
        }

        return $TargetObject.Properties.storageProfile.osDisk.osType -eq 'Linux' -or
        $Assert.HasField($TargetObject, 'properties.osProfile.linuxConfiguration').Result -or
            (IsLinuxOffering($TargetObject.Properties.storageProfile.imageReference))
    }
}

function global:VMSSHasLinuxOS {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param ()
    process {
        if ($PSRule.TargetType -ne 'Microsoft.Compute/virtualMachineScaleSets') {
            return $False;
        }

        return $TargetObject.Properties.virtualMachineProfile.storageProfile.osDisk.osType -eq 'Linux' -or
        $Assert.HasField($TargetObject, 'properties.virtualMachineProfile.osProfile.linuxConfiguration').Result -or
            (IsLinuxOffering($TargetObject.Properties.virtualMachineProfile.storageProfile.imageReference))
    }
}

$Global:FlagSupportsTagWarning = $True;

# Determines if the object supports tags
function global:SupportsTags {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param (
        [String]$TargetType = $PSRule.TargetType
    )
    begin {
        if ($Global:FlagSupportsTagWarning) {
            Write-Warning -Message "The 'SupportsTags' PowerShell function has been replaced with the selector 'Azure.Resource.SupportsTags'. The 'SupportsTags' function is deprecated and will no longer work in the next major version. Please update your PowerShell rules to the selector instead. See https://aka.ms/ps-rule-azure/upgrade.";
            $Global:FlagSupportsTagWarning = $False;
        }
    }
    process {
        if (
            ($TargetType -eq 'Microsoft.Subscription') -or
            ($TargetType -eq 'Microsoft.Resources/deployments') -or
            ($TargetType -eq 'Microsoft.AzureActiveDirectory/b2ctenants') -or
            ($TargetType -notLike 'Microsoft.*/*') -or
            ($TargetType -like 'Microsoft.Addons/*') -or
            ($TargetType -like 'Microsoft.Advisor/*') -or
            ($TargetType -like 'Microsoft.Authorization/*') -or
            ($TargetType -like 'Microsoft.Billing/*') -or
            ($TargetType -like 'Microsoft.Blueprint/*') -or
            ($TargetType -like 'Microsoft.Capacity/*') -or
            ($TargetType -like 'Microsoft.Classic*') -or
            ($TargetType -like 'Microsoft.Consumption/*') -or
            ($TargetType -like 'Microsoft.Gallery/*') -or
            ($TargetType -like 'Microsoft.Security/*') -or
            ($TargetType -like 'microsoft.support/*') -or
            ($TargetType -like 'Microsoft.WorkloadMonitor/*') -or
            ($TargetType -like '*/providers/roleAssignments') -or
            ($TargetType -like '*/providers/diagnosticSettings') -or

            # Exclude sub-resources by default
            ($TargetType -like 'Microsoft.*/*/*' -and !(
                $TargetType -eq 'Microsoft.Automation/automationAccounts/runbooks' -or
                $TargetType -eq 'Microsoft.Automation/automationAccounts/configurations' -or
                $TargetType -eq 'Microsoft.Automation/automationAccounts/compilationjobs' -or
                $TargetType -eq 'Microsoft.Automation/automationAccounts/modules' -or
                $TargetType -eq 'Microsoft.Automation/automationAccounts/nodeConfigurations' -or
                $TargetType -eq 'Microsoft.Automation/automationAccounts/python2Packages' -or
                $TargetType -eq 'Microsoft.Automation/automationAccounts/watchers' -or
                $TargetType -eq 'Microsoft.Resources/templateSpecs/versions'
            )) -or

            # Some exception to resources (https://docs.microsoft.com/azure/azure-resource-manager/management/tag-support#microsoftresources)
            ($TargetType -like 'Microsoft.Resources/*' -and !(
                $TargetType -eq 'Microsoft.Resources/deploymentScripts' -or
                $TargetType -eq 'Microsoft.Resources/resourceGroups' -or
                $TargetType -eq 'Microsoft.Resources/templateSpecs' -or
                $TargetType -eq 'Microsoft.Resources/templateSpecs/versions'
            )) -or

            # Some exception to resources (https://docs.microsoft.com/azure/azure-resource-manager/management/tag-support#microsoftinsights)
            ($TargetType -like 'Microsoft.Insights/*' -and !(
                $TargetType -eq 'Microsoft.Insights/actionGroups' -or
                $TargetType -eq 'Microsoft.Insights/activityLogAlerts' -or
                $TargetType -eq 'Microsoft.Insights/alertRules' -or
                $TargetType -eq 'Microsoft.Insights/autoscaleSettings' -or
                $TargetType -eq 'Microsoft.Insights/components' -or
                $TargetType -eq 'Microsoft.Insights/dataCollectionEndpoints' -or
                $TargetType -eq 'Microsoft.Insights/dataCollectionRules' -or
                $TargetType -eq 'Microsoft.Insights/guestDiagnosticSettings' -or
                $TargetType -eq 'Microsoft.Insights/metricAlerts' -or
                $TargetType -eq 'Microsoft.Insights/notificationGroups' -or
                $TargetType -eq 'Microsoft.Insights/privateLinkScopes' -or
                $TargetType -eq 'Microsoft.Insights/scheduledQueryRules' -or
                $TargetType -eq 'Microsoft.Insights/webTests' -or
                $TargetType -eq 'Microsoft.Insights/workbooks' -or
                $TargetType -eq 'Microsoft.Insights/workbookTemplates'
            )) -or

            # Some exceptions to resources (https://docs.microsoft.com/azure/azure-resource-manager/management/tag-support#microsoftcostmanagement)
            ($TargetType -like 'Microsoft.CostManagement/*' -and !(
                $TargetType -eq 'Microsoft.CostManagement/Connectors'
            ))
        ) {
            return $False;
        }
        return $True;
    }
}

# Determines if the object supports regions
function global:SupportsRegions {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param ()
    process {
        if (
            ($PSRule.TargetType -eq 'Microsoft.Subscription') -or
            ($PSRule.TargetType -eq 'Microsoft.AzureActiveDirectory/b2cDirectories') -or
            ($PSRule.TargetType -eq 'Microsoft.Network/trafficManagerProfiles') -or
            ($PSRule.TargetType -like 'Microsoft.Authorization/*') -or
            ($PSRule.TargetType -like 'Microsoft.Consumption/*') -or
            ($PSRule.TargetType -like '*/providers/roleAssignments') -or
            ($TargetObject.Location -eq 'global')
        ) {
            return $False;
        }
        return $True;
    }
}

function global:ConvertToUInt64 {
    param (
        [Parameter(Mandatory = $True)]
        [System.Net.IPAddress]$IP
    )

    process {
        $bytes = $IP.GetAddressBytes();
        $size = $bytes.Length;

        [System.UInt64]$result = 0;

        for ($i = 0; $i -lt $size; $i++) {
            $result = ($result -shl 8) + $bytes[$i];
        }
        return $result;
    }
}

function global:GetIPAddressCount {
    [CmdletBinding()]
    [OutputType([System.UInt64])]
    param (
        [Parameter(Mandatory = $True)]
        [String]$Start,

        [Parameter(Mandatory = $True)]
        [String]$End
    )
    process {
        $startIP = [System.Net.IPAddress]::Parse($Start);
        $endIP = [System.Net.IPAddress]::Parse($End);

        $startAddress = ConvertToUInt64 -IP $startIP;
        $endAddress = ConvertToUInt64 -IP $endIP;

        if ($endAddress -ge $startAddress) {
            return $endAddress - $startAddress + 1;
        }
        else {
            return $startAddress - $endAddress + 1;
        }
    }
}

function global:GetIPAddressSummary {
    [CmdletBinding()]
    [OutputType([PSObject])]
    param ()
    process {
        $firewallRules = @($TargetObject.resources | Where-Object -FilterScript {
                $_.Type -like '*/firewallRules'
            } | ForEach-Object -Process {
                if (!($_.ResourceName -eq 'AllowAllWindowsAzureIps' -or ($_.properties.startIpAddress -eq '0.0.0.0' -and $_.properties.endIpAddress -eq '0.0.0.0'))) {
                    $_;
                }
            })

        $private = 0;
        $public = 0;

        foreach ($fwRule in $firewallRules) {
            if ($fwRule.Properties.startIpAddress -like '10.*' -or $fwRule.Properties.startIpAddress -like '172.*' -or $fwRule.Properties.startIpAddress -like '192.168.*') {
                $private += GetIPAddressCount -Start $fwRule.Properties.startIpAddress -End $fwRule.Properties.endIpAddress;
            }
            else {
                $public += GetIPAddressCount -Start $fwRule.Properties.startIpAddress -End $fwRule.Properties.endIpAddress;
            }
        }
        return [PSCustomObject]@{
            Private = $private
            Public  = $public
        }
    }
}

function global:GetCIDRMask {
    [CmdletBinding()]
    [OutputType([PSObject])]
    param (
        [Parameter(Mandatory = $True)]
        [String]$CIDR
    )
    process {
        $cidrParts = $CIDR.Split('/');
        $ip = ConvertToUInt64 -IP ([System.Net.IPAddress]::Parse($cidrParts[0]));
        [System.UInt64]$mask = 4294967295;
        if ($cidrParts.Length -eq 2) {
            $mask = [System.UInt64](4294967295 -shl (32 - ([System.Byte]::Parse($cidrParts[1])))) -band 4294967295;
        }
        return [PSCustomObject]@{
            Mask = $mask
            IP   = $ip;
        }
    }
}

function global:WithinCIDR {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param (
        [Parameter(Mandatory = $True)]
        [String]$IP,

        [Parameter(Mandatory = $True)]
        [String[]]$CIDR
    )
    process {
        [System.UInt64]$address = ConvertToUInt64 -IP ([System.Net.IPAddress]::Parse($IP));
        $result = $False;

        for ($i = 0; (($i -lt $CIDR.Length) -and (!$result)); $i++) {
            $mask = GetCIDRMask -CIDR $CIDR[$i];
            $result = ($mask.Mask -band $address) -eq $mask.IP;
        }
        return $result;
    }
}

# Normalizes the location for comparison.
function global:GetNormalLocation {
    [CmdletBinding()]
    [OutputType([String])]
    param (
        [Parameter(Mandatory = $True)]
        [AllowEmptyString()]
        [String]$Location
    )
    process {
        return $Location.Replace(' ', '').ToLower();
    }
}

function global:GetAvailabilityZone {
    [CmdletBinding()]
    [OutputType([String[]])]
    param (
        [Parameter(Mandatory = $True)]
        [AllowEmptyString()]
        [string]$Location,

        [Parameter(Mandatory = $True)]
        [AllowEmptyCollection()]
        [PSObject[]]$Zone
    )
    process {
        $normalizedLocation = GetNormalLocation -Location $Location;
        $availabilityZones = $Zone | Where-Object { (GetNormalLocation -Location $_.Location) -eq $normalizedLocation } | Select-Object -ExpandProperty Zones -First 1;
        return $availabilityZones | Sort-Object { [int]$_ };
    }
}

function global:PrependConfigurationZoneWithProviderZone {
    [CmdletBinding()]
    [OutputType([PSObject[]])]
    param (
        [Parameter(Mandatory = $True)]
        [AllowEmptyCollection()]
        [PSObject[]]$ConfigurationZone,

        [Parameter(Mandatory = $True)]
        [AllowEmptyCollection()]
        [PSObject[]]$ProviderZone
    )

    process {
        if ($ConfigurationZone.Length -gt 0) {

            # Prepend configuration options and provider mappings together
            # We put configuration options at the beginning so they are processed first
            return @($ConfigurationZone) + @($ProviderZone);
        }
        
        return $ProviderZone;
    }
}

function global:HasOMSOrAMAExtension {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param ()
    process {
        if ($PSRule.TargetType -eq 'Microsoft.Compute/virtualMachines') {
            $extensions = @(GetSubResources -ResourceType 'Microsoft.Compute/virtualMachines/extensions' |
                Where-Object { ($_.Properties.publisher -eq 'Microsoft.EnterpriseCloud.Monitoring') -or ($_.Properties.publisher -eq 'Microsoft.Azure.Monitor') })
            
            $Assert.Greater($extensions, '.', 0).Result
        }
        elseif ($PSRule.TargetType -eq 'Microsoft.Compute/virtualMachineScaleSets') {
            $property = $TargetObject.Properties.virtualMachineProfile.extensionProfile.extensions.properties |
                Where-Object { ($_.publisher -eq 'Microsoft.EnterpriseCloud.Monitoring') -or ($_.publisher -eq 'Microsoft.Azure.Monitor') }
                    $subresource = @(GetSubResources -ResourceType 'Microsoft.Compute/virtualMachineScaleSets/extensions' |
                        Where-Object { ($_.Properties.publisher -eq 'Microsoft.EnterpriseCloud.Monitoring') -or ($_.Properties.publisher -eq 'Microsoft.Azure.Monitor') })
                      
            $extensions = @($property; $subresource)
            $Assert.Greater($extensions, '.', 0).Result
        }
    }
}

# SIG # Begin signature block
# MIInrQYJKoZIhvcNAQcCoIInnjCCJ5oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDYtQgDFnj9KTuo
# gBWwdmRZ4CD184fd4sFkzz+OIRejxKCCDYEwggX/MIID56ADAgECAhMzAAACzI61
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
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgOpcZTTVc
# DjXoqhN3KYKFQ//MPRDZkUrC6U52d5v/P3owQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQCPvKCe+emnk9eMBR+5cRza/vXpTSl/lonb+XSprF8S
# qrvGHePb+dqETT0J96zHm//KOp0RgAf2LC0G4YtxfZWz8yKG8ZmwdMwriu/4rYQk
# +ercHqodHxMdk4n9drBmQfJ3IPXQ27AkLKf/r+TGKmO4o7O81eZobxp/nTTndwnK
# 02HnFoTrWAV7jp0aMr7u7GavM0gHb5gP4y1QXoqfoRZ+5LKNIzA1IeULlTXopKob
# hCvSq5/3odnKVwqwpRYtmqcEh8k89jRl23vB3Xvy97AGy+ZQS8H6RrhUPuY5GBXn
# asd0v6T9ZJv0LXdmlI1+pzq3Thxcye8+qDOD1+mZqZgtoYIXDDCCFwgGCisGAQQB
# gjcDAwExghb4MIIW9AYJKoZIhvcNAQcCoIIW5TCCFuECAQMxDzANBglghkgBZQME
# AgEFADCCAVUGCyqGSIb3DQEJEAEEoIIBRASCAUAwggE8AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIHT6LWaphKgu2MZgWVd8uoAQc4o9xWwTqIfk96x1
# wUeKAgZjYs2HO/8YEzIwMjIxMTA5MTgwNzU4LjY3OVowBIACAfSggdSkgdEwgc4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1p
# Y3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMg
# VFNTIEVTTjozMkJELUUzRDUtM0IxRDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgU2VydmljZaCCEV8wggcQMIIE+KADAgECAhMzAAABrfzfTVjjXTLpAAEA
# AAGtMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# MB4XDTIyMDMwMjE4NTEzNloXDTIzMDUxMTE4NTEzNlowgc4xCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVy
# YXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjozMkJE
# LUUzRDUtM0IxRDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vydmlj
# ZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOieUyqlTSrVLhvY7TO8
# vgC+T5N/y/MXeR3oNwE0rLI1Eg/gM5g9NhP+KqqJc/7uPL4TsoALb+RVf6roYNll
# yQrYmquUjwsq262MD5L9l9rU1plz2tMPehP8addVlNIjYIBh0NC4CyME6txVppQr
# 7eFd/bW0X9tnZy1aDW+zoaJB2FY8haokq5cRONEW4uoVsTTXsICkbYOAYffIIGak
# MFXVvB30NcsuiDn6uDk83XXTs0tnSr8FxzPoD8SgPPIcWaWPEjCQLr5I0BxfdUli
# wNPHIPEglqosrClRjXG7rcZWbWeODgATi0i6DUsv1Wn0LOW4svK4/Wuc/v9dlmuI
# ramv9whbgCykUuYZy8MxTzsQqU2Rxcm8h89CXA5jf1k7k3ZiaLUJ003MjtTtNXzl
# gb+k1A5eL17G3C4Ejw5AoViM+UBGQvxuTxpFeaGoQFqeOGGtEK0qk0wdUX9p/4Au
# 9Xsle5D5fvypBdscXBslUBcT6+CYq0kQ9smsTyhV4DK9wb9Zn7ObEOfT0AQyppI6
# jwzBjHhAGFyrKYjIbglMaEixjRv7XdNic2VuYKyS71A0hs6dbbDx/V7hDbdv2srt
# Z2VTO0y2E+4QqMRKtABv4AggjYKz5TYGuQ4VbbPY8fBO9Xqva3Gnx1ZDOQ3nGVFK
# HwarGDcNdB3qesvtJbIGJgJjAgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQUfVB0HQS8
# qiFabmqEqOV9LrLGwVkwHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIw
# XwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9w
# cy9jcmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3Js
# MGwGCCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENB
# JTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcD
# CDANBgkqhkiG9w0BAQsFAAOCAgEAi9AdRbsx/gOSdBXndwRejQuutQqce3k3bgs1
# slPjZSx6FDXp1IZzjOyT1Jo/3eUWDBFJdi+Heu1NoyDdGn9vL6rxly1L68K4MnfL
# Bm+ybyjN+xa1eNa4+4cOoOuxE2Kt8jtmZbIhx2jvY7F9qY/lanR5PSbUKyClhNQh
# xsnNUp/JSQ+o7nAuQJ+wsCwPCrXYE7C+TvKDja6e6WU0K4RiBXFGU1z6Mt3K9wlM
# D/QGU4+/IGZDmE+/Z/k0JfJjZyxCAlcmhe3rgdhDzAsGxJYq4PblGZTBdr8wkQwp
# P2jggyMMawMM5DggwvXaDbrqCQ8gksNhCZzTqfS2dbgLF0m7HfwlUMrcnzi/bdTS
# RWzIXg5QsH1t5XaaIH+TZ1uZBtwXJ8EOXr6S+2A6q8RQVY10KnBH6YpGE9OhXPfu
# Iu882muFEdh4EXbPdARUR1IMSIxg88khSBC/YBwQhCpjTksq5J3Z+jyHWZ4MnXX5
# R42mAR584iRYc7agYvuotDEqcD0U9lIjgW31PqfqZQ1tuYZTiGcKE9QcYGvZFKnV
# dkqK8V0M9e+kF5CqDOrMMYRV2+I/FhyQsJHxK/G53D0O5bvdIh2gDnEHRAFihdZj
# 29Z7W0paGPotGX0oB5r9wqNjM3rbvuEe6FJ323MPY1x9/N1g126T/SokqADJBTKq
# yBYN4zMwggdxMIIFWaADAgECAhMzAAAAFcXna54Cm0mZAAAAAAAVMA0GCSqGSIb3
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
# MSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjozMkJELUUzRDUtM0IxRDElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUA
# QJLRrUVR4ZbBDgWPjuNqVctUzpCggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFt
# cCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOcV3X0wIhgPMjAyMjExMDkxMjA0
# MTNaGA8yMDIyMTExMDEyMDQxM1owdzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5xXd
# fQIBADAKAgEAAgIa1gIB/zAHAgEAAgIRezAKAgUA5xcu/QIBADA2BgorBgEEAYRZ
# CgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0G
# CSqGSIb3DQEBBQUAA4GBAElZXpzIfi85uBBgpu6Fux7/BmQIgKgtHe2h2XdkSyki
# AOX44S0SCJcRedCR3fPsODFy8XNq2H2ZoxJWwuOPT2GCXU/viSkxUeOJEcbC9r16
# Pox/dLFhA4nqCXYjXP6P+Z25HtpvHZCuOP44cH89zXJinVUDOHILKvbWHreQHH6P
# MYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMA
# AAGt/N9NWONdMukAAQAAAa0wDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJ
# AzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgI8oGXDeWTDL8cZgSVJyl
# eOD+8BWXtR7bOud+xUVCBkgwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCCf
# 6nw9CR5e1+Ottcn1w992Kmn8YMTY/DWPIHeMbMtQgjCBmDCBgKR+MHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABrfzfTVjjXTLpAAEAAAGtMCIEIGb+
# nN5I9+f7KNTxvsNMQM2E0G9cnUvoU1Tvt0MsqoRVMA0GCSqGSIb3DQEBCwUABIIC
# ADN2tv18mrSvkhqLqqJkulwY/D1sr91OdQLHnJ/k7eim9I6vZcXoMMULjdQfTWSr
# 65krd3MHybTs895igO+1ZVA7537TDhpKhMRgjx1I0pl9IBQ0H5myImB6TjMHbxzd
# 7ccLxyQ+53vvhvlWYgm76qZIWYP6nIY8hph1OsltDTm8dHQJbzz0sMwtksp7kCTc
# J+o0O6MA+FV8CgNPBxtXiqsIlCCBQ8MuJ5yeGr6iO7xBole03O+VVhMguyTLffeU
# UxsZiRV/yVjhypLxqn6mltmAKQ5Vt748WL/Q+75o+LcQAQ/8+5kY/eaitVnwUVZl
# GfDIf3d0vhOP3p6AViXNjDXGkggJjbFiJ1VD4U3dGC65QOjyAfREwixgOKRBWqqD
# RByqnftkcedlmqEolNXSwGw+xWoIScSM9NpfBPN2Q6Gtx3frEq4u1ihjF4Tbz9x5
# hI7TYTKjmqdZ7ssws3p49FccnOZ+4yIJyFfo40pnYGN6Q5FTirLbbRqNk/5jNw0J
# 6oz8sdr9yAlTbBoNGljGhToWVDEh0kjH/w6BuVrewhjn7H9WYRNcC5jqvTyEbGUv
# 2xK+hfVcDNt2clsUOjjotnGDLDMw6xO+Zp4cm2yj7szgDbeq4lt9Fu5vvd2GZVj5
# nP27Gr9Y4ntJ1BCXapJqg5r6tsRTv9aZgXIwJU4/vUxh
# SIG # End signature block
