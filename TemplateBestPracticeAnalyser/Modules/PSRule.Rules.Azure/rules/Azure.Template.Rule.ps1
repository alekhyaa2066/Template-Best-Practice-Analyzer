# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#
# Validation rules for Azure template and parameter files
#

#region Template

# Synopsis: Use ARM template file structure.
Rule 'Azure.Template.TemplateFile' -Ref 'AZR-000212' -Type '.json' -If { (IsTemplateFile) } -Tag @{ release = 'GA'; ruleSet = '2020_06' } {
    $jsonObject = $PSRule.GetContentFirstOrDefault($TargetObject);
    $Assert.HasFields($jsonObject, @('$schema', 'contentVersion', 'resources'));
    $jsonObject.PSObject.Properties | Within 'Name' '$schema', 'contentVersion', 'metadata', 'parameters', 'functions', 'variables', 'resources', 'outputs';
}

# Synopsis: Use a more recent version of the Azure template schema.
Rule 'Azure.Template.TemplateSchema' -Ref 'AZR-000213' -Type '.json' -If { (IsTemplateFile) } -Tag @{ release = 'GA'; ruleSet = '2021_09'; } {
    $jsonObject = $PSRule.GetContentFirstOrDefault($TargetObject);
    $Assert.HasJsonSchema($jsonObject, @(
        'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json'
        'https://schema.management.azure.com/schemas/2018-05-01/subscriptionDeploymentTemplate.json'
        'https://schema.management.azure.com/schemas/2019-08-01/tenantDeploymentTemplate.json'
        'https://schema.management.azure.com/schemas/2019-08-01/managementGroupDeploymentTemplate.json'
    ), $True);
}

# Synopsis: Use a Azure template schema with the https scheme.
Rule 'Azure.Template.TemplateScheme' -Ref 'AZR-000214' -Type '.json' -If { (IsTemplateFile) } -Tag @{ release = 'GA'; ruleSet = '2021_09'; } {
    $jsonObject = $PSRule.GetContentFirstOrDefault($TargetObject);
    $Assert.StartsWith($jsonObject, '$schema', 'https://');
}

# Synopsis: Use template parameter descriptions.
Rule 'Azure.Template.ParameterMetadata' -Ref 'AZR-000215' -Type '.json' -If { (IsTemplateFile) } -Tag @{ release = 'GA'; ruleSet = '2020_09' } {
    $parameters = @(GetTemplateParameters);
    if ($parameters.Length -eq 0) {
        return $Assert.Pass();
    }
    foreach ($parameter in $parameters) {
        $Assert.HasFieldValue($parameter.value, 'metadata.description').
            Reason($LocalizedData.TemplateParameterDescription, $parameter.name);
    }
}

# Synopsis: ARM templates should include at least one resource.
Rule 'Azure.Template.Resources' -Ref 'AZR-000216' -Type '.json' -If { (IsTemplateFile) } -Tag @{ release = 'GA'; ruleSet = '2020_09' } {
    $jsonObject = $PSRule.GetContent($TargetObject)[0];
    $Assert.GreaterOrEqual($jsonObject, 'resources', 1);
}

# Synopsis: ARM template parameters should be used at least once.
Rule 'Azure.Template.UseParameters' -Ref 'AZR-000217' -Type '.json' -If { (IsTemplateFile) } -Tag @{ release = 'GA'; ruleSet = '2020_09' } {
    $jsonContent = Get-Content -Path $TargetObject.FullName -Raw;
    $parameters = @(GetTemplateParameters);
    if ($parameters.Length -eq 0) {
        return $Assert.Pass();
    }
    foreach ($parameter in $parameters) {
        $Assert.Match($jsonContent, '.', "\`"\[[\s\S]*parameters\(\s{0,}'$($parameter.name.Replace('$', '\$'))'\s{0,}\)[\s\S]*\]\`"").
            Reason($LocalizedData.ParameterNotFound, $parameter.name);
    }
}

# Synopsis: Each Azure Resource Manager (ARM) template file should contain a minimal number of parameters.
Rule 'Azure.Template.DefineParameters' -Ref 'AZR-000218' -Type '.json' -If { (IsTemplateFile) -and !(IsGenerated) } -Tag @{ release = 'GA'; ruleSet = '2021_03'; } {
    $parameters = @(GetTemplateParameters);
    $Assert.GreaterOrEqual($parameters, '.', 1);
}

# Synopsis: ARM template variables should be used at least once.
Rule 'Azure.Template.UseVariables' -Ref 'AZR-000219' -Type '.json' -If { (IsTemplateFile) } -Tag @{ release = 'GA'; ruleSet = '2020_09' } {
    $jsonObject = $PSRule.GetContent($TargetObject)[0];
    $jsonContent = Get-Content -Path $TargetObject.FullName -Raw;
    $variableNames = @($jsonObject.variables.PSObject.Properties | Where-Object { $_.MemberType -eq 'NoteProperty' } | ForEach-Object {
        $variable = $_;
        if ($variable.name -eq 'copy') {
            $variable.value | ForEach-Object {
                $_.name;
            }
        }
        else {
            $variable.name;
        }
    });
    if ($variableNames.Length -eq 0) {
        return $Assert.Pass();
    }
    foreach ($variableName in $variableNames) {
        $Assert.Match($jsonContent, '.', "\`"\[[\s\S]*variables\(\s{0,}'$([System.Text.RegularExpressions.Regex]::Escape($variableName))'\s{0,}\)[\s\S]*\]\`"").
            Reason($LocalizedData.VariableNotFound, $variableName);
    }
}

# Synopsis: Set the default value for location parameters within ARM template to the default value to `[resourceGroup().location]`.
Rule 'Azure.Template.LocationDefault' -Ref 'AZR-000220' -Type '.json' -If { (HasLocationParameter) } -Tag @{ release = 'GA'; ruleSet = '2021_03' } {
    # https://github.com/Azure/arm-ttk/blob/master/arm-ttk/testcases/deploymentTemplate/Location-Should-Not-Be-Hardcoded.test.ps1

    $parameters = @(GetTemplateParameters -Name 'location');
    foreach ($parameter in $parameters) {
        if ($Assert.HasFieldValue($parameter.Value, 'defaultValue', 'global').Result) {
            $Assert.Pass();
        }
        else {
            $defaultValue = [PSRule.Rules.Azure.Runtime.Helper]::CompressExpression($parameter.Value.defaultValue);
            $Assert.HasFieldValue($defaultValue, '.', '[resourceGroup().location]').
                Reason($LocalizedData.ParameterInvalidDefaultValue, $parameter.Name, $parameter.Value.defaultValue);
        }
    }
}

# Synopsis: Location parameters should use a string value.
Rule 'Azure.Template.LocationType' -Ref 'AZR-000221' -Type '.json' -If { (HasLocationParameter) } -Tag @{ release = 'GA'; ruleSet = '2021_03'; } {
    # https://github.com/Azure/arm-ttk/blob/master/arm-ttk/testcases/deploymentTemplate/Location-Should-Not-Be-Hardcoded.test.ps1

    $parameters = @(GetTemplateParameters -Name 'location');
    foreach ($parameter in $parameters) {
        $Assert.HasFieldValue($parameter.Value, 'type', 'string');
    }
}

# Synopsis: Template resource location should be an expression or `global`.
Rule 'Azure.Template.ResourceLocation' -Ref 'AZR-000222' -Type '.json' -If { (HasTemplateResources) } -Tag @{ release = 'GA'; ruleSet = '2021_03'; } {
    # https://github.com/Azure/arm-ttk/blob/master/arm-ttk/testcases/deploymentTemplate/Resources-Should-Have-Location.test.ps1

    $resources = @(GetTemplateResources);
    if ($resources.Length -eq 0) {
        return $Assert.Pass();
    }
    foreach ($resource in $resources) {
        AnyOf {
            $Assert.NotHasField($resource, 'location');
            $Assert.HasFieldValue($resource, 'location', 'global');
            $Assert.Match($resource, 'location', '^\[.*\]$');
        }
    }
}

# Synopsis: Template should reference a location parameter to specify resource location.
Rule 'Azure.Template.UseLocationParameter' -Ref 'AZR-000223' -Level Warning -Type '.json' -If { (IsTemplateFile -Suffix '/deploymentTemplate.json') -and !(IsGenerated) } -Tag @{ release = 'GA'; ruleSet = '2021_03'; } {
    $jsonObject = $PSRule.GetContent($TargetObject)[0];
    if ($Assert.HasField($jsonObject, 'parameters.location').Result) {
        $jsonObject.parameters.PSObject.Properties.Remove('location')
    }
    $content = $jsonObject | ConvertTo-Json -Depth 100;
    $Assert.NotMatch($content, '.', 'resourceGroup\(\s{0,}\)\.location').
        Reason($LocalizedData.ExpressionInTemplate, 'resourceGroup().location');
}

# Synopsis: Template parameters `minValue` and `maxValue` constraints must be valid.
Rule 'Azure.Template.ParameterMinMaxValue' -Ref 'AZR-000224' -Type '.json' -If { (HasTemplateParameters) } -Tag @{ release = 'GA'; ruleSet = '2021_03'; } {
    # https://github.com/Azure/arm-ttk/blob/master/arm-ttk/testcases/deploymentTemplate/Min-And-Max-Value-Are-Numbers.test.ps1

    # Get parameters with either minValue or maxValue
    $parameters = @(GetTemplateParameters | Where-Object {
        $Assert.HasField($_.Value, @('minValue', 'maxValue')).Result
    });
    if ($parameters.Length -eq 0) {
        return $Assert.Pass();
    }
    foreach ($parameter in $parameters) {
        $Assert.HasFieldValue($parameter.Value, 'type', 'int');
        if ($Assert.HasField($parameter.Value, 'minValue').Result) {
            $Assert.IsInteger($parameter.Value, 'minValue').
                Reason($LocalizedData.ParameterTypeMismatch, 'minValue', $parameter.Name, 'int');
        }
        if ($Assert.HasField($parameter.Value, 'maxValue').Result) {
            $Assert.IsInteger($parameter.Value, 'maxValue').
            Reason($LocalizedData.ParameterTypeMismatch, 'maxValue', $parameter.Name, 'int');
        }
    }
}

# Synopsis: Use default deployment detail level for nested deployments.
Rule 'Azure.Template.DebugDeployment' -Ref 'AZR-000225' -Type '.json' -If { (HasTemplateResources) } -Tag @{ release = 'GA'; ruleSet = '2021_03'; } {
    # https://github.com/Azure/arm-ttk/blob/master/arm-ttk/testcases/deploymentTemplate/Deployment-Resources-Must-Not-Be-Debug.test.ps1

    # Get deployments
    $resources = @($PSRule.GetContent($TargetObject)[0].resources | Where-Object {
        $Assert.HasFieldValue($_, 'type', 'Microsoft.Resources/deployments').Result
    });
    if ($resources.Length -eq 0) {
        return $Assert.Pass();
    }
    foreach ($resource in $resources) {
        $Assert.HasDefaultValue($resource, 'properties.debugSetting.detailLevel', 'None');
    }
}

# Synopsis: Set the parameter default value to a value of the same type.
Rule 'Azure.Template.ParameterDataTypes' -Ref 'AZR-000226' -Type '.json' -If { (HasTemplateParameters) } -Tag @{ release = 'GA'; ruleSet = '2021_03'; } {
    $jsonObject = $PSRule.GetContent($TargetObject)[0];
    $parameters = @($jsonObject.parameters.PSObject.Properties);
    if ($parameters.Length -eq 0) {
        return $Assert.Pass();
    }
    foreach ($parameter in $parameters) {
        if (!$Assert.HasField($parameter.Value, 'defaultValue').Result) {
            # No defaultValue
            $Assert.Pass();
        }
        elseif ($parameter.Value.defaultValue -is [string] -and $parameter.Value.defaultValue.StartsWith('[') -and $parameter.Value.defaultValue.EndsWith(']')) {
            # Is function
            $Assert.Pass();
        }
        elseif ($Null -eq $parameter.Value.defaultValue)
        {
            # defaultValue is null
            $Assert.Pass();
        }
        elseif ($parameter.Value.type -eq 'bool') {
            $Assert.IsBoolean($parameter.Value, 'defaultValue').
                Reason($LocalizedData.ParameterTypeMismatch, 'defaultValue', $parameter.Name, $parameter.Value.type);
        }
        elseif ($parameter.Value.type -eq 'int') {
            $Assert.IsInteger($parameter.Value, 'defaultValue').
                Reason($LocalizedData.ParameterTypeMismatch, 'defaultValue', $parameter.Name, $parameter.Value.type);
        }
        elseif ($parameter.Value.type -eq 'array') {
            $Assert.IsArray($parameter.Value, 'defaultValue').
                Reason($LocalizedData.ParameterTypeMismatch, 'defaultValue', $parameter.Name, $parameter.Value.type);
        }
        elseif ($parameter.Value.type -eq 'string' -or $parameter.Value.type -eq 'secureString') {
            $Assert.IsString($parameter.Value, 'defaultValue').
                Reason($LocalizedData.ParameterTypeMismatch, 'defaultValue', $parameter.Name, $parameter.Value.type);
        }
        elseif ($parameter.Value.type -eq 'object' -or $parameter.Value.type -eq 'secureObject') {
            $Assert.TypeOf($parameter.Value, 'defaultValue', [PSObject]).
                Reason($LocalizedData.ParameterTypeMismatch, 'defaultValue', $parameter.Name, $parameter.Value.type);
        }
    }
}

# Synopsis: Set the parameter value to a value that matches the specified strong type.
Rule 'Azure.Template.ParameterStrongType' -Ref 'AZR-000227' -Type 'Microsoft.Resources/deployments' -Tag @{ release = 'GA'; ruleSet = '2021_12'; } {
    $Assert.Create($PSRule.Issue.Get('PSRule.Rules.Azure.Template.ParameterStrongType'));
}

# Synopsis: Template expressions should not exceed the maximum length.
Rule 'Azure.Template.ExpressionLength' -Ref 'AZR-000228' -Type 'Microsoft.Resources/deployments' -Tag @{ release = 'GA'; ruleSet = '2021_12'; } {
    $Assert.Create($PSRule.Issue.Get('PSRule.Rules.Azure.Template.ExpressionLength'));
}

#endregion Template

#region Parameters

# Synopsis: Use ARM parameter file structure.
Rule 'Azure.Template.ParameterFile' -Ref 'AZR-000229' -Type '.json' -If { (IsParameterFile) } -Tag @{ release = 'GA'; ruleSet = '2020_06' } {
    $jsonObject = $PSRule.GetContentFirstOrDefault($TargetObject);
    $Assert.HasFields($jsonObject, @('$schema', 'contentVersion', 'parameters'));
    $jsonObject.PSObject.Properties | Within 'Name' '$schema', 'contentVersion', 'metadata', 'parameters';
}

# Synopsis: Use a Azure template parameter schema with the https scheme.
Rule 'Azure.Template.ParameterScheme' -Ref 'AZR-000230' -Type '.json' -If { (IsParameterFile) } -Tag @{ release = 'GA'; ruleSet = '2021_09'; } {
    $jsonObject = $PSRule.GetContentFirstOrDefault($TargetObject);
    $Assert.StartsWith($jsonObject, '$schema', 'https://');
}

# Synopsis: Configure a metadata link for each parameter file.
Rule 'Azure.Template.MetadataLink' -Ref 'AZR-000231' -Type '.json' -If { $Configuration.AZURE_PARAMETER_FILE_METADATA_LINK -eq $True -and (IsParameterFile) } -Tag @{ release = 'GA'; ruleSet = '2021_09' } {
    $jsonObject = $PSRule.GetContentFirstOrDefault($TargetObject);
    $field = $Assert.HasFieldValue($jsonObject, 'metadata.template');
    if (!$field.Result) {
        return $field;
    }
    $path = [PSRule.Rules.Azure.Runtime.Helper]::GetMetadataLinkPath($TargetObject.FullName, $jsonObject.metadata.template)
    $Assert.FilePath($path, '.');
    $Assert.WithinPath($path, '.', @($PWD));
}

# Synopsis: Specify a value for each parameter in template parameter files.
Rule 'Azure.Template.ParameterValue' -Ref 'AZR-000232' -Type '.json' -If { (IsParameterFile) } -Tag @{ release = 'GA'; ruleSet = '2021_09'; } {
    $jsonObject = $PSRule.GetContentFirstOrDefault($TargetObject);
    $parameters = @($jsonObject.parameters.PSObject.Properties | Where-Object {
        $_.MemberType -eq 'NoteProperty'
    });
    if ($parameters.Length -eq 0) {
        return $Assert.Pass();
    }
    foreach ($parameter in $parameters) {
        if ($Assert.HasField($parameter.Value, 'value').Result -or $Assert.HasFieldValue($parameter.Value, 'reference').Result) {
            $Assert.Pass();
        }
        else {
            $Assert.Fail($LocalizedData.ParameterValueNotSet, $parameter.Name);
        }
    }
}

# Synopsis: Use a valid secret reference within parameter files.
Rule 'Azure.Template.ValidSecretRef' -Ref 'AZR-000233' -Type '.json' -If { (IsParameterFile) } -Tag @{ release = 'GA'; ruleSet = '2021_09'; } {
    $jsonObject = $PSRule.GetContentFirstOrDefault($TargetObject);
    $parameters = @($jsonObject.parameters.PSObject.Properties | Where-Object {
        $_.MemberType -eq 'NoteProperty' -and $Assert.HasField($_.Value, 'reference').Result
    });
    if ($parameters.Length -eq 0) {
        return $Assert.Pass();
    }
    foreach ($parameter in $parameters) {
        $Assert.Match($parameter.Value, 'reference.keyVault.id', '^\/subscriptions\/(.+?)\/resourceGroups\/(.+?)\/providers\/Microsoft\.KeyVault\/vaults\/[A-Za-z](-|[A-Za-z0-9])*[A-Za-z0-9]$');
        $Assert.Match($parameter.Value, 'reference.secretName', '^[A-Za-z0-9-]{1,127}$');
    }
}

# Synopsis: Use comments for each resource in ARM template to communicate purpose.
Rule 'Azure.Template.UseComments' -Ref 'AZR-000234' -Level Information -Type '.json' -If { (IsTemplateFile) -and !(IsGenerated) } -Tag @{ release = 'GA'; ruleSet = '2021_12'; } {
    $resources = @(GetTemplateResources | Where-Object { $Assert.NullOrEmpty($_, 'comments').Result });

    $Assert.Count($resources, '.', 0).Reason(
        $LocalizedData.TemplateResourceWithoutComment,
        $TargetObject.FullName,
        $resources.Length
    );
}

# Synopsis: Use descriptions for each resource in generated template(bicep, psarm, AzOps) to communicate purpose.
Rule 'Azure.Template.UseDescriptions' -Ref 'AZR-000235' -Level Information -Type '.json' -If { (IsTemplateFile) -and (IsGenerated) } -Tag @{ release = 'GA'; ruleSet = '2021_12'; } {
    $resources = @(GetTemplateResources | Where-Object { $Assert.NullOrEmpty($_, 'metadata.description').Result });

    $Assert.Count($resources, '.', 0).Reason(
        $LocalizedData.TemplateResourceWithoutDescription,
        $TargetObject.FullName,
        $resources.Length
    );
}

#endregion Parameters

#region Helper functions

# Determines if the object is a Azure Resource Manager template file
function global:IsTemplateFile {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param (
        [Parameter(Mandatory = $False)]
        [String]$Suffix
    )
    process {
        if ($PSRule.TargetType -ne '.json') {
            return $False;
        }
        try {
            $jsonObject = $PSRule.GetContent($TargetObject)[0];
            [String]$targetSchema = $jsonObject.'$schema';
            $schemas = @(
                # Https
                "https://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json`#"
                "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json`#"
                "https://schema.management.azure.com/schemas/2018-05-01/subscriptionDeploymentTemplate.json`#"
                "https://schema.management.azure.com/schemas/2019-08-01/tenantDeploymentTemplate.json`#"
                "https://schema.management.azure.com/schemas/2019-08-01/managementGroupDeploymentTemplate.json`#"

                # Http
                "http://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json`#"
                "http://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json`#"
                "http://schema.management.azure.com/schemas/2018-05-01/subscriptionDeploymentTemplate.json`#"
                "http://schema.management.azure.com/schemas/2019-08-01/tenantDeploymentTemplate.json`#"
                "http://schema.management.azure.com/schemas/2019-08-01/managementGroupDeploymentTemplate.json`#"
            )
            return $targetSchema -in $schemas -and ([String]::IsNullOrEmpty($Suffix) -or $targetSchema.Trim("`#").EndsWith($Suffix));
        }
        catch {
            return $False;
        }
    }
}

# Determines if the object is a Azure Resource Manager parameter file
function global:IsParameterFile {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param ()
    process {
        if ($PSRule.TargetType -ne '.json') {
            return $False;
        }
        try {
            $jsonObject = $PSRule.GetContent($TargetObject)[0];
            $schemas = @(
                # Https
                "https://schema.management.azure.com/schemas/2015-01-01/deploymentParameters.json`#"
                "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json`#"
                "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json`#"
                "https://schema.management.azure.com/schemas/2018-05-01/subscriptionDeploymentParameters.json`#"
                "https://schema.management.azure.com/schemas/2019-08-01/tenantDeploymentParameters.json`#"
                "https://schema.management.azure.com/schemas/2019-08-01/managementGroupDeploymentParameters.json`#"

                # Http
                "http://schema.management.azure.com/schemas/2015-01-01/deploymentParameters.json`#"
                "http://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json`#"
                "http://schema.management.azure.com/schemas/2018-05-01/subscriptionDeploymentParameters.json`#"
                "http://schema.management.azure.com/schemas/2019-08-01/tenantDeploymentParameters.json`#"
                "http://schema.management.azure.com/schemas/2019-08-01/managementGroupDeploymentParameters.json`#"
            )
            return $jsonObject.'$schema' -in $schemas;
        }
        catch {
            return $False;
        }
    }
}

function global:HasLocationParameter {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param ()
    process {
        if (!(IsTemplateFile -Suffix '/deploymentTemplate.json')) {
            return $False;
        }
        $jsonObject = $PSRule.GetContent($TargetObject)[0];
        return $Assert.HasField($jsonObject, 'parameters.location').Result;
    }
}

function global:HasTemplateParameters {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param ()
    process {
        if (!(IsTemplateFile)) {
            return $False;
        }
        $parameters = @($PSRule.GetContent($TargetObject)[0].parameters.PSObject.Properties | Where-Object {
            $_.MemberType -eq 'NoteProperty'
        });
        return $Assert.GreaterOrEqual($parameters, '.', 1).Result;
    }
}

function global:HasTemplateResources {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param ()
    process {
        if (!(IsTemplateFile)) {
            return $False;
        }
        $jsonObject = $PSRule.GetContent($TargetObject)[0].resources;
        return $Assert.GreaterOrEqual($jsonObject, '.', 1).Result;
    }
}

function global:GetTemplateParameters {
    [CmdletBinding()]
    [OutputType([PSObject])]
    param (
        [Parameter(Mandatory = $False)]
        [String[]]$Name
    )
    process {
        $parameters = @($PSRule.GetContent($TargetObject)[0].parameters.PSObject.Properties | Where-Object {
            $_.MemberType -eq 'NoteProperty'
        });
        return $parameters | Where-Object {
            $Null -eq $Name -or $_.Name -in $Name
        };
    }
}

function global:GetTemplateResources {
    [CmdletBinding()]
    [OutputType([PSObject])]
    param ()
    process {
        $PSRule.GetContent($TargetObject)[0].resources | ForEach-Object {
            # Emit each resource
            $_;

            # Emit resources in nested templates
            if ($Assert.HasFieldValue($_, 'type', 'Microsoft.Resources/deployments').Result -and $Assert.GreaterOrEqual($_, 'properties.template.resources', 1).Result) {
                $_.properties.template.resources;
            }
            # Emit sub-resources
            elseif ($Assert.GreaterOrEqual($_, 'resources', 1).Result) {
                $_.resources;
            }
        }
    }
}

function global:IsGenerated {
    [CmdletBinding()]
    param ()
    process {
        if ($PSRule.TargetType -ne '.json') {
            return $False;
        }
        try {
            $jsonObject = $PSRule.GetContentFirstOrDefault($TargetObject);
            return $Assert.In($jsonObject, 'metadata._generator.name', @('bicep', 'psarm', 'AzOps')).Result;
        }
        catch {
            return $False;
        }
    }
}

#endregion Helper functions

# SIG # Begin signature block
# MIInrQYJKoZIhvcNAQcCoIInnjCCJ5oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDO/dQ2M49C6jRb
# p+ChM3V6gt2/AAjo3JMCDPkfYs56eqCCDYEwggX/MIID56ADAgECAhMzAAACzI61
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
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg5bAf/Nxc
# o9cDCQqoTkgKOtQZvvyH0axjl9t8+rnIg90wQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQA43wgtrdj56HL1eOXHvkPJiLoHKe4kZKV/nCcK6jm6
# haWODoebzgeKfWLEe0WCx7Unc1oyYcS1HuEhmkigN3mx58fixY9AixbV2ml1b5MN
# pce+KNzJ+B8/G1upwXGzZUOI9JPkFqpEbPCHJAAr9MIPAcEyTEs3S3c/cLQUQ7NC
# 3ub9aU5lLeUGolXCGo1IROcpYTC8JDm/77GwU2fgTKyvKh99LduphMLFYtyksSKI
# 1gCxHVASGjHr3rlmsyNwz8DvbY+8Qo0P0O3uB9CD5iR9dT/pzvDdZmuSAyk+CVfn
# s/bMgMtCcIynOqoc5q7cMGmlhbW00KrB6CQQFDQU3zANoYIXDDCCFwgGCisGAQQB
# gjcDAwExghb4MIIW9AYJKoZIhvcNAQcCoIIW5TCCFuECAQMxDzANBglghkgBZQME
# AgEFADCCAVUGCyqGSIb3DQEJEAEEoIIBRASCAUAwggE8AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEICQ6F/BwqewtoQVSh5hTm0i9WZBCMq2jsSOstoqw
# ApFEAgZjYr4oB6YYEzIwMjIxMTA5MTgwNzUxLjMyNlowBIACAfSggdSkgdEwgc4x
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
# AzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgZHph6UMXLpTpxoz6Fbu+
# QUkjVFb8Lsa7nyqvCYxGJwgwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCB0
# /ssdAMsHwnNwhfFBXPlFnRvWhHqSX9YLUxBDl1xlpjCBmDCBgKR+MHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABqFXwYanMMBhcAAEAAAGoMCIEIBtV
# vgRmvVCNfhhiXCzrSm0JQBAk+675oKmIgCOAL0IGMA0GCSqGSIb3DQEBCwUABIIC
# AEpApXZSV4a2gue3GE8RcYRmDLH+FnLbAbLsAYo1o/yyIF6SWedyUTyLoMUZj5+w
# XKRH3rHel9p/1SZtq67iujBSwvJavV8Js/kErh08feDNeo4xcccsGt3q4pNC8Lmz
# qgUNdMTewIYYyHhPnAx/pSoFy8F18rIFAQSv5dQMkZNUT1rRxpUrbav7dssSryFZ
# iFxDQatSGTHXngDf1pPeSMOpiMz3NmhzzvP6F1AEjaaX/RD3+eSxURGpG3+wuyK4
# xllOfTAEsJI4fcxFz2HWv6Dr6u4EsLU7qAtKqpOoXaYrj/OpSm+T0a+GBC71pcpN
# Jm0aeLXd8ifsfx2lGZghm89KUQkyUZX6jyK5GBi3bwy8lO6Z8xwnHBUPlJaf2G03
# 7V+3k6/GNRXzs8SSOaFMGOBsYz+glf4I2Xo/SdTEIo1yPSibyRgtpE9lsb1vgaw7
# lwEex87JKOHIJhuT40K/ovAdenosOHnQquj+Y1TQuZemfeUyZWkPTpzZv9a1cC90
# wdiZ7j0S/FG42ly+9slC3cDD6r6MgSk+FDKUDFugWqtcg+K3cfxb4nafREJ4mYi6
# u9zA4DBZOeex2Wf8LgOiZi9oOHwRyMIqBr1boEXeXrMrY0vofH/ll7BljRlMRLFT
# YVA1TgwM+VpIBa/auuZF1mqUKfwjrE4fAgCXJykhOWVX
# SIG # End signature block
