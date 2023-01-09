# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#
# Validation rules for API Management
#

# Synopsis: Enforce HTTPS for communication to API clients.
Rule 'Azure.APIM.HTTPEndpoint' -Ref 'AZR-000042' -Type 'Microsoft.ApiManagement/service', 'Microsoft.ApiManagement/service/apis' -Tag @{ release = 'GA'; ruleSet = '2020_06'; 'Azure.WAF/pillar' = 'Security'; } -Labels @{ 'Azure.ASB.v3/control' = 'DP-3' } {
    if ($PSRule.TargetType -eq 'Microsoft.ApiManagement/service') {
        $apis = @(GetSubResources -ResourceType 'Microsoft.ApiManagement/service/apis')
        if ($apis.Length -eq 0) {
            return $Assert.Pass();
        }
        foreach ($api in $apis) {
            $Assert.NotIn($api, 'properties.protocols', @('http'))
        }
    }
    elseif ($PSRule.TargetType -eq 'Microsoft.ApiManagement/service/apis') {
        $Assert.NotIn($TargetObject, 'properties.protocols', @('http'))
    }
}

# Synopsis: APIs should have descriptors set
Rule 'Azure.APIM.APIDescriptors' -Ref 'AZR-000043' -Level Warning -Type 'Microsoft.ApiManagement/service', 'Microsoft.ApiManagement/service/apis' -Tag @{ release = 'GA'; ruleSet = '2020_09' } {
    $apis = @($TargetObject);
    if ($PSRule.TargetType -eq 'Microsoft.ApiManagement/service') {
        $apis = @(GetSubResources -ResourceType 'Microsoft.ApiManagement/service/apis');
    }
    if ($apis.Length -eq 0) {
        return $Assert.Pass();
    }
    foreach ($api in $apis) {
        $Assert.
            HasFieldValue($api, 'Properties.displayName').
            Reason($LocalizedData.APIMDescriptors, 'API', $api.name, 'displayName');
        $Assert.
            HasFieldValue($api, 'Properties.description').
            Reason($LocalizedData.APIMDescriptors, 'API', $api.name, 'description');
    }
}

# Synopsis: Use HTTPS for communication to backend services.
Rule 'Azure.APIM.HTTPBackend' -Ref 'AZR-000044' -Type 'Microsoft.ApiManagement/service', 'Microsoft.ApiManagement/service/backends', 'Microsoft.ApiManagement/service/apis' -Tag @{ release = 'GA'; ruleSet = '2020_06'; 'Azure.WAF/pillar' = 'Security'; } -Labels @{ 'Azure.ASB.v3/control' = 'DP-3' } {
    $apis = @();
    $backends = @();

    if ($PSRule.TargetType -eq 'Microsoft.ApiManagement/service') {
        $backends = @(GetSubResources -ResourceType 'Microsoft.ApiManagement/service/backends' | Where-Object {
            $Assert.HasField($_, 'properties.url').Result
        });
        $apis = @(GetSubResources -ResourceType 'Microsoft.ApiManagement/service/apis' | Where-Object {
            $Assert.HasField($_, 'properties.serviceUrl').Result
        });
    }
    elseif ($PSRule.TargetType -eq 'Microsoft.ApiManagement/service/apis') {
        if ($Assert.HasField($TargetObject, 'properties.serviceUrl').Result) {
            $apis = @($TargetObject)
        }
    }
    elseif ($PSRule.TargetType -eq 'Microsoft.ApiManagement/service/backends') {
        if ($Assert.HasField($TargetObject, 'properties.url').Result) {
            $backends = @($TargetObject)
        }
    }

    if ($backends.Length -eq 0 -and $apis.Length -eq 0) {
        return $Assert.Pass();
    }
    foreach ($backend in $backends) {
        $Assert.
            NotStartsWith($backend, 'properties.url', 'http://').
            Reason($LocalizedData.BackendUrlNotHttps, $backend.name);
    }
    foreach ($api in $apis) {
        $Assert.
            NotStartsWith($api, 'properties.serviceUrl', 'http://').
            Reason($LocalizedData.ServiceUrlNotHttps, $api.name);
    }
}

# Synopsis: Encrypt all named values
Rule 'Azure.APIM.EncryptValues' -Ref 'AZR-000045' -Type 'Microsoft.ApiManagement/service', 'Microsoft.ApiManagement/service/properties', 'Microsoft.ApiManagement/service/namedValues' -Tag @{ release = 'GA'; ruleSet = '2020_06'; 'Azure.WAF/pillar' = 'Security'; } -Labels @{ 'Azure.ASB.v3/control' = @('IM-8', 'DP-7') } {
    $properties = @($TargetObject);
    if ($PSRule.TargetType -eq 'Microsoft.ApiManagement/service') {
        $properties = @(GetSubResources -ResourceType 'Microsoft.ApiManagement/service/properties', 'Microsoft.ApiManagement/service/namedValues');
    }
    if ($properties.Length -eq 0) {
        return $Assert.Pass();
    }
    foreach ($property in $properties) {
        $Assert.
            HasFieldValue($property, 'properties.secret', $True).
            WithReason(($LocalizedData.APIMSecretNamedValues -f $property.name), $True);
    }
}

# Synopsis: Require subscription for products
Rule 'Azure.APIM.ProductSubscription' -Ref 'AZR-000046' -Type 'Microsoft.ApiManagement/service', 'Microsoft.ApiManagement/service/products' -Tag @{ release = 'GA'; ruleSet = '2020_06' } {
    $products = @($TargetObject);
    if ($PSRule.TargetType -eq 'Microsoft.ApiManagement/service') {
        $products = @(GetSubResources -ResourceType 'Microsoft.ApiManagement/service/products');
    }
    if ($products.Length -eq 0) {
        return $Assert.Pass();
    }
    foreach ($product in $products) {
        $Assert.
            HasFieldValue($product, 'Properties.subscriptionRequired', $True).
            WithReason(($LocalizedData.APIMProductSubscription -f $product.Name), $True);
    }
}

# Synopsis: Require approval for products
Rule 'Azure.APIM.ProductApproval' -Ref 'AZR-000047' -Type 'Microsoft.ApiManagement/service', 'Microsoft.ApiManagement/service/products' -Tag @{ release = 'GA'; ruleSet = '2020_06' } {
    $products = @($TargetObject);
    if ($PSRule.TargetType -eq 'Microsoft.ApiManagement/service') {
        $products = @(GetSubResources -ResourceType 'Microsoft.ApiManagement/service/products');
    }
    if ($products.Length -eq 0) {
        return $Assert.Pass();
    }
    foreach ($product in $products) {
        $Assert.
            HasFieldValue($product, 'Properties.approvalRequired', $True).
            WithReason(($LocalizedData.APIMProductApproval -f $product.Name), $True);
    }
}

# Synopsis: Remove sample products
Rule 'Azure.APIM.SampleProducts' -Ref 'AZR-000048' -Type 'Microsoft.ApiManagement/service', 'Microsoft.ApiManagement/service/products' -Tag @{ release = 'GA'; ruleSet = '2020_06' } {
    $products = @($TargetObject);
    if ($PSRule.TargetType -eq 'Microsoft.ApiManagement/service') {
        $products = @(GetSubResources -ResourceType 'Microsoft.ApiManagement/service/products');
    }
    if ($products.Length -eq 0) {
        return $Assert.Pass();
    }
    foreach ($product in $products) {
        $Assert.NotIn($product, 'Name', @('unlimited', 'starter'))
    }
}

# Synopsis: Products should have descriptors set
Rule 'Azure.APIM.ProductDescriptors' -Ref 'AZR-000049' -Level Warning -Type 'Microsoft.ApiManagement/service', 'Microsoft.ApiManagement/service/products' -Tag @{ release = 'GA'; ruleSet = '2020_09' } {
    $products = @($TargetObject);
    if ($PSRule.TargetType -eq 'Microsoft.ApiManagement/service') {
        $products = @(GetSubResources -ResourceType 'Microsoft.ApiManagement/service/products');
    }
    if ($products.Length -eq 0) {
        return $Assert.Pass();
    }
    foreach ($product in $products) {
        $Assert.
            HasFieldValue($product, 'Properties.displayName').
            WithReason(($LocalizedData.APIMDescriptors -f 'product', $product.name, 'displayName'), $True);
        $Assert.
            HasFieldValue($product, 'Properties.description').
            WithReason(($LocalizedData.APIMDescriptors -f 'product', $product.name, 'description'), $True);
    }
}

# Synopsis: Use product terms
Rule 'Azure.APIM.ProductTerms' -Ref 'AZR-000050' -Type 'Microsoft.ApiManagement/service', 'Microsoft.ApiManagement/service/products' -Tag @{ release = 'GA'; ruleSet = '2020_09' } {
    $products = @($TargetObject);
    if ($PSRule.TargetType -eq 'Microsoft.ApiManagement/service') {
        $products = @(GetSubResources -ResourceType 'Microsoft.ApiManagement/service/products');
    }
    if ($products.Length -eq 0) {
        return $Assert.Pass();
    }
    foreach ($product in $products) {
        $Assert.
            HasFieldValue($product, 'Properties.terms').
            WithReason(($LocalizedData.APIMProductTerms -f $product.name), $True);
    }
}

# Synopsis: Renew expired certificates
Rule 'Azure.APIM.CertificateExpiry' -Ref 'AZR-000051' -Type 'Microsoft.ApiManagement/service' -Tag @{ release = 'GA'; ruleSet = '2020_06'; 'Azure.WAF/pillar' = 'Security'; } -Labels @{ 'Azure.ASB.v3/control' = 'DP-7' } {
    $configurations = @($TargetObject.Properties.hostnameConfigurations | Where-Object {
        $Null -ne $_.certificate
    })
    if ($configurations.Length -eq 0) {
        return $Assert.Pass();
    }
    foreach ($configuration in $configurations) {
        $remaining = ($configuration.certificate.expiry - [DateTime]::Now).Days;
        $Assert.
            GreaterOrEqual($remaining, '.', $Configuration.Azure_MinimumCertificateLifetime).
            WithReason(($LocalizedData.APIMCertificateExpiry -f $configuration.hostName, $configuration.certificate.expiry.ToString('yyyy/MM/dd')), $True);
    }
} -Configure @{ Azure_MinimumCertificateLifetime = 30 }

# Synopsis: API management services deployed with Premium SKU should use availability zones in supported regions for high availability.
Rule 'Azure.APIM.AvailabilityZone' -Ref 'AZR-000052' -Type 'Microsoft.ApiManagement/service' -If { IsPremiumAPIM } -Tag @{ release = 'GA'; ruleSet = '2021_12' } {
    $apiManagementServiceProvider = [PSRule.Rules.Azure.Runtime.Helper]::GetResourceType('Microsoft.ApiManagement', 'service');

    $configurationZoneMappings = $Configuration.AZURE_APIM_ADDITIONAL_REGION_AVAILABILITY_ZONE_LIST;
    $providerZoneMappings = $apiManagementServiceProvider.ZoneMappings;
    $mergedAvailabilityZones = PrependConfigurationZoneWithProviderZone -ConfigurationZone $configurationZoneMappings -ProviderZone $providerZoneMappings;

    $primaryLocationAvailabilityZones = GetAvailabilityZone -Location $TargetObject.Location -Zone $mergedAvailabilityZones;

    # Validate primary location availability zones
    if (-not $primaryLocationAvailabilityZones) {
        $Assert.Pass();
    }
    else {
        $hasValidUnits = $Assert.GreaterOrEqual($TargetObject, 'sku.capacity', $TargetObject.zones.Length).Result;
        $hasValidZones = $Assert.GreaterOrEqual($TargetObject, 'zones', 2).Result;

        $Assert.Create(
            ($hasValidUnits -and $hasValidZones),
            $LocalizedData.APIMAvailabilityZone, 
            $TargetObject.name, 
            $TargetObject.Location, 
            ($primaryLocationAvailabilityZones -join ', ')
        )
    }

    # Also validate any additional locations that are added to APIM
    if (-not $Assert.NullOrEmpty($TargetObject, 'Properties.additionalLocations').Result) {

        foreach ($additionalLocation in $TargetObject.Properties.additionalLocations) {
            $additionalLocationAvailabilityZones = GetAvailabilityZone -Location $additionalLocation.Location -Zone $mergedAvailabilityZones;

            if (-not $additionalLocationAvailabilityZones) {
                $Assert.Pass();
            }
            else {
                $hasValidUnits = $Assert.GreaterOrEqual($additionalLocation, 'sku.capacity', $additionalLocation.zones.Length).Result;
                $hasValidZones = $Assert.GreaterOrEqual($additionalLocation, 'zones', 2).Result;

                $Assert.Create(
                    ($hasValidUnits -and $hasValidZones),
                    $LocalizedData.APIMAvailabilityZone, 
                    $TargetObject.name, 
                    $additionalLocation.Location, 
                    ($additionalLocationAvailabilityZones -join ', ')
                );
            }
        }
    }
} -Configure @{ AZURE_APIM_ADDITIONAL_REGION_AVAILABILITY_ZONE_LIST = @() }

#region Helper functions

function global:IsPremiumAPIM {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param ()
    process {
        return $Assert.HasFieldValue($TargetObject, 'sku.name', 'Premium').Result;
    }
}

#endregion Helper functions
# SIG # Begin signature block
# MIInrQYJKoZIhvcNAQcCoIInnjCCJ5oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAqp+E0Ez1SljGC
# 1/WoAEnltmvK8sM74TkDVQF4urUATaCCDYEwggX/MIID56ADAgECAhMzAAACzI61
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
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg0JU6neQN
# GITziA0MEbT5ne6ByLQ0w7ea5ip4MaUeckMwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQAytVP/gajNaYoWhAykn6k/fd7HZmdTxyUTxJuPOfGy
# JBtlpJqtBe7MMoxJTL1ph3BhqcPRZ308FqbGT1oHcuIFLf4FKdk1yzBL5nJj+hsw
# ZDtjuT4ZEDGZy1pjOHSLioSi7d0xDZHarWMd3U0pUEF53WlTMB+XihcZBXxGfepx
# uRc/UYRh2iM4FN6EbwMsEDKKmaKTyf7J4hwa3lnaYyD56s3t9+JH7BlHa8NT+7Pp
# 91nkeYtSSd35p3+tyrDbpVGW+hc8Qu4C8giQll6ItIi20I6q8UQ+/fLLTuoE80cb
# 8aulqg1qTgtaMi+u/57ZerHI7JIcAL1786ju+anNOrvHoYIXDDCCFwgGCisGAQQB
# gjcDAwExghb4MIIW9AYJKoZIhvcNAQcCoIIW5TCCFuECAQMxDzANBglghkgBZQME
# AgEFADCCAVUGCyqGSIb3DQEJEAEEoIIBRASCAUAwggE8AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIPkxmJ8ykLtjgyH3pyXD+1xWMt0aAN+gGinjAjxk
# kjUJAgZjYszJ8bIYEzIwMjIxMTA5MTgwNzQ5Ljc4NVowBIACAfSggdSkgdEwgc4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1p
# Y3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMg
# VFNTIEVTTjpEOURFLUUzOUEtNDNGRTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgU2VydmljZaCCEV8wggcQMIIE+KADAgECAhMzAAABrGa8hyJd3j17AAEA
# AAGsMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# MB4XDTIyMDMwMjE4NTEyOVoXDTIzMDUxMTE4NTEyOVowgc4xCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVy
# YXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpEOURF
# LUUzOUEtNDNGRTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vydmlj
# ZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMd4C1DFF2Lux3HMK8AE
# lMdTF4iG9ROyKQWFehTXe+EX1QOrTBFnhMAKNHIQWoxkK1W62/oQQQmtIHo8sphM
# t1WpkLNvCm3La8sdVL3t/BAx7UWkmfvujJ3KDaSgt3clc5uNPUj7e32U4n/Ep9oO
# c+Pv/EHc7XGH1fGRvLRYzwoxP1xkKleusbIzT/aKn6WC2BggPzjHXin9KE7kriCu
# qA+JNhskkedTHJQIotblR+rZcsexTSmjO+Z7R0mfeHiU8DntvZvZ/9ad9XUhDwUJ
# FKZ8ZZvxnqnZXwFYkDKNagY8g06BF1vDulblAs6A4huP1e7ptKFppB1VZkLUAmIW
# 1xxJGs3keidATWIVx22sGVyemaT29NftDp/jRsDw/ahwv1Nkv6WvykovK0kDPIY9
# TCW9cRbvUeElk++CVM7cIqrl8QY3mgEQ8oi45VzEBXuY04Y1KijbGLYRFNUypXMR
# DApV+kcjG8uST13mSCf2iMhWRRLz9/jyIwe7lmXz4zUyYckr+2Nm8GrSq5fVAPsh
# IO8Ab/aOo6/oe3G3Y+cil8iyRJLJNxbMYxiQJKZvbxlCIp+pGInaD1373M7KPPF/
# yXeT4hG0LqXKvelkgtlpzefPrmUVupjYTgeGfupUwFzymSk4JRNO1thRB0bDKDIy
# NMVqEuvV1UxdcricV0ojgeJHAgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQUWBGfdwTL
# H0BnSjx8SVqYWsBAjk0wHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIw
# XwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9w
# cy9jcmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3Js
# MGwGCCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENB
# JTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcD
# CDANBgkqhkiG9w0BAQsFAAOCAgEAedC1AlhVXHCldk8toIzAW9QyITcReyhUps1u
# D67zCC308fRzYFES/2vMX7o0ObJgzCxT1ni0vkcs8WG2MUIsk91RCPIeDzTQItIp
# j9ZTz9h0tufcKGm3ahknRs1hoV12jRFkcaqXJo1fsyuoKgD+FTT2lOvrEsNjJh5w
# Esi+PB/mVmh/Ja0Vu8jhUJc1hrBUQ5YisQ4N00snZwhOoCePXbdD6HGs1cmsXZbr
# kT8vNPYV8LnI4lxuJ/YaYS20qQr6Y9DIHFDNYxZbTlsQeXs/KjnhRNdFiCGoAcLH
# WweWeRszh2iUhMfY1/79d7somfjx6ZyJPZOr4fE0UT2l/rBaBTroPpDOvpaOsY6E
# /teLLMfynr6UOQeE4lRiw59siVGyAGqpTBTbdzAFLBFH40ubr7VEldmjiHa14EkZ
# xYvcgzKxKqub4yrKafo/j9aUbwLrL2VMHWcpa18Jhv6zIjd01IGkUdj3UJ+JKQNA
# z5eyPyQSZPt9ws8bynodGlM5nYkHBy7rPvj45y+Zz7jrLgjgvZIixGszwqKyKJ47
# APHxrH8GjCQusbvW9NF4LAYKoZZGj7PwmQA+XmwD5tfUQ0KuzMRFmMpOUztiTAgJ
# jQf9TMuc3pYmpFWEr8ksYdwrjrdWYALCXA/IQXEdAisQwj5YzTsh4QxTUq+vRSxs
# 93yB3nIwggdxMIIFWaADAgECAhMzAAAAFcXna54Cm0mZAAAAAAAVMA0GCSqGSIb3
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
# MSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpEOURFLUUzOUEtNDNGRTElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUA
# sRrSE7C4sEn96AMhjNkXZ0Y1iqCggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFt
# cCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOcV3MkwIhgPMjAyMjExMDkxMjAx
# MTNaGA8yMDIyMTExMDEyMDExM1owdzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5xXc
# yQIBADAKAgEAAgIOaQIB/zAHAgEAAgIRKzAKAgUA5xcuSQIBADA2BgorBgEEAYRZ
# CgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0G
# CSqGSIb3DQEBBQUAA4GBAC0PQIlP2u+oNeKmbp9Lao+SJIh/YTOa1dqj0BaxXv/2
# ltsd2VLY2y62TavqUdqZaWSljXWI6M0zEJ8SRXXjdhX/FVtLH1vWF3gKBYk5aJ1d
# HCMVXbeA2/l/7c+jOJFTvHW0FXQ9XpX0QtBfC0PhJgCePdnv0vEHiEraLX/lGqlq
# MYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMA
# AAGsZryHIl3ePXsAAQAAAawwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJ
# AzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgp6rAcEuSE05em8EWDT/T
# FsDQWTksblSI0NlFpRiOiJwwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCD5
# twGSgzgvCXEAcrVz56m79Pp+bQJf+0+Lg2faBCzC9TCBmDCBgKR+MHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABrGa8hyJd3j17AAEAAAGsMCIEIAkT
# psTzRHI8G9U7ZRx+43aNimEGdHmAS3VnG6fqKNY8MA0GCSqGSIb3DQEBCwUABIIC
# ACkX2JGizWMIsBTj2bdeQtC2doJTmHx3d1AIEjCv5oZCCpIgN+ktacBGxNt8N42/
# SOrftcaneKKJbM+9WC9Xej7fwsq2FDNInxo/d9aISZx3eMre3UTr6nm1oChqNzsH
# qiynbXcjopHLC0dNlm7abQQPLB588Z7jbnHE0iWkfHc22bU+UBP7DFh/NTVoW3Yo
# t3MdxMaP4dnVFLGutN9PcyYUIlaf5THqFoh/HH0UEAwAf49yijcdtgV3ueSxAIKV
# cyilODS2qMe28LrwXBcLUkYx9o40Rs84GYL2jAnF/QlLtHKbsWWe9kLZ/T9ML2rB
# MTcXNofopXfGp8/PxJzAaiUiEOCZNbOocuztVAJaxpRO8CuO5wVx0Vk0mfHF1aqX
# 3Wn8rNMYaUKrpTphEPttWZNOu5mvkDgBmgMZQXm6zZSeymjJ3iWFMtn0tGnGUVnD
# 08y489hVUyOq8F9hl3xMzJb625JZkG27wh/kZANPMSUeyTPPLkmhXU+ghqqvUyXf
# JcmVdeTIrPfSwJJP49lKcEyz/+h9w5DBRKJisaTpo7wm7kXi34tjHkaTZZUifMF4
# N03nwSKPIj7Ui4lbZZ+X4cQR+zHlCJ1J36kpvt+5q44MHJ+qEgMOBjWoMOWwVM27
# OZxfSIFdm1UxMbvMuXagrilpSb5BhzSIYEEPVMUSZXzt
# SIG # End signature block
