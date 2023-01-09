# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#
# PSRule.Rules.Azure module
#

$m = Import-Module 'Az.Resources' -MinimumVersion 5.6.0 -Global -ErrorAction SilentlyContinue -PassThru;
if ($Null -eq $m) {
    Write-Warning -Message "To use PSRule for Azure export cmdlets please install Az.Resources.";
}

Set-StrictMode -Version latest;

[PSRule.Rules.Azure.Configuration.PSRuleOption]::UseExecutionContext($ExecutionContext);

#
# Localization
#

#
# Public functions
#

#region Public functions

# .ExternalHelp PSRule.Rules.Azure-help.xml
function Export-AzRuleData {
    [CmdletBinding(SupportsShouldProcess = $True, DefaultParameterSetName = 'Default')]
    [OutputType([System.IO.FileInfo])]
    [OutputType([PSObject])]
    param (
        [Parameter(Position = 0, Mandatory = $False)]
        [String]$OutputPath = $PWD,

        # Filter by Subscription name or id
        [Parameter(Mandatory = $False, ParameterSetName = 'Default')]
        [String[]]$Subscription = $Null,

        # Filter by Tenant id
        [Parameter(Mandatory = $False, ParameterSetName = 'Default')]
        [String[]]$Tenant = $Null,

        # Filter by Resource Group name
        [Parameter(Mandatory = $False)]
        [String[]]$ResourceGroupName = $Null,

        # Filter by Tag
        [Parameter(Mandatory = $False)]
        [Hashtable]$Tag,

        [Parameter(Mandatory = $False)]
        [Switch]$PassThru = $False,

        [Parameter(Mandatory = $False, ParameterSetName = 'All')]
        [Switch]$All = $False
    )
    begin {
        Write-Verbose -Message "[Export-AzRuleData] BEGIN::";
    }
    process {
        # Get subscriptions
        $context = FindAzureContext -Subscription $Subscription -Tenant $Tenant -All:$All -Verbose:$VerbosePreference;

        if ($Null -eq $context) {
            return;
        }
        if (!(Test-Path -Path $OutputPath)) {
            if ($PSCmdlet.ShouldProcess('Create output directory', $OutputPath)) {
                $Null = New-Item -Path $OutputPath -ItemType Directory -Force;
            }
        }

        $getParams = @{ };
        $filterParams = @{ };

        if ($PSBoundParameters.ContainsKey('Tag')) {
            $getParams['Tag'] = $Tag;
        }
        if ($PSBoundParameters.ContainsKey('ResourceGroupName')) {
            $getParams['ResourceGroupName'] = $ResourceGroupName;
            $filterParams['ResourceGroupName'] = $ResourceGroupName;
        }

        foreach ($c in $context) {
            Write-Verbose -Message "[Export] -- Using subscription: $($c.Subscription.Name)";
            $filePath = Join-Path -Path $OutputPath -ChildPath "$($c.Subscription.Id).json";
            GetAzureResource @getParams -Context $c -Verbose:$VerbosePreference `
            | FilterAzureResource @filterParams -Verbose:$VerbosePreference `
            | ExportAzureResource -Path $filePath -PassThru $PassThru -Verbose:$VerbosePreference;
        }
    }
    end {
        Write-Verbose -Message "[Export-AzRuleData] END::";
    }
}

# .ExternalHelp PSRule.Rules.Azure-help.xml
function Export-AzRuleTemplateData {
    [CmdletBinding()]
    [OutputType([System.IO.FileInfo])]
    [OutputType([PSObject])]
    param (
        [Parameter(Position = 0, Mandatory = $False)]
        [String]$Name,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]$TemplateFile,

        [Parameter(Mandatory = $False, ValueFromPipelineByPropertyName = $True)]
        [Alias('TemplateParameterFile')]
        [String[]]$ParameterFile,

        [Parameter(Mandatory = $False)]
        [Alias('ResourceGroupName')]
        [PSRule.Rules.Azure.Configuration.ResourceGroupReference]$ResourceGroup,

        [Parameter(Mandatory = $False)]
        [PSRule.Rules.Azure.Configuration.SubscriptionReference]$Subscription,

        [Parameter(Mandatory = $False)]
        [String]$OutputPath = $PWD,

        [Parameter(Mandatory = $False)]
        [Switch]$PassThru = $False
    )
    begin {
        Write-Verbose -Message '[Export-AzRuleTemplateData] BEGIN::';
        if ($MyInvocation.InvocationName -eq 'Export-AzTemplateRuleData') {
            Write-Warning -Message "The cmdlet 'Export-AzTemplateRuleData' is has been renamed to 'Export-AzRuleTemplateData'. Use of 'Export-AzTemplateRuleData' is deprecated and will be removed in the next major version."
        }

        $Option = [PSRule.Rules.Azure.Configuration.PSRuleOption]::FromFileOrDefault($PWD);
        $Option.Output.Path = $OutputPath;

        # Build the pipeline
        $builder = [PSRule.Rules.Azure.Pipeline.PipelineBuilder]::Template($Option);
        $builder.Deployment($Name);
        $builder.PassThru($PassThru);

        # Bind to subscription context
        if ($PSBoundParameters.ContainsKey('Subscription')) {
            $subscriptionOption = GetSubscription -InputObject $Subscription -ErrorAction SilentlyContinue;
            if ($Null -ne $subscriptionOption) {
                $builder.Subscription($subscriptionOption);
            }
        }
        # Bind to resource group
        if ($PSBoundParameters.ContainsKey('ResourceGroup')) {
            $resourceGroupOption = GetResourceGroup -InputObject $ResourceGroup -ErrorAction SilentlyContinue;
            if ($Null -ne $resourceGroupOption) {
                $builder.ResourceGroup($resourceGroupOption);
            }
        }

        $builder.UseCommandRuntime($PSCmdlet);
        $builder.UseExecutionContext($ExecutionContext);
        try {
            $pipeline = $builder.Build();
            $pipeline.Begin();
        }
        catch {
            $pipeline.Dispose();
        }
    }
    process {
        if ($Null -ne (Get-Variable -Name pipeline -ErrorAction SilentlyContinue)) {
            try {
                $source = [PSRule.Rules.Azure.Pipeline.TemplateSource]::new($TemplateFile, $ParameterFile);
                $pipeline.Process($source);
            }
            catch {
                $pipeline.Dispose();
                throw;
            }
        }
    }
    end {
        if ($Null -ne (Get-Variable -Name pipeline -ErrorAction SilentlyContinue)) {
            try {
                $pipeline.End();
            }
            finally {
                $pipeline.Dispose();
            }
        }
        Write-Verbose -Message '[Export-AzRuleTemplateData] END::';
    }
}

# .ExternalHelp PSRule.Rules.Azure-help.xml
function Get-AzRuleTemplateLink {
    [CmdletBinding()]
    [OutputType([PSRule.Rules.Azure.Data.Metadata.ITemplateLink])]
    param (
        [Parameter(Position = 1, Mandatory = $False, ValueFromPipelineByPropertyName = $True)]
        [Alias('f', 'TemplateParameterFile', 'FullName')]
        [SupportsWildcards()]
        [String[]]$InputPath = '*.parameters.json',

        [Parameter(Mandatory = $False)]
        [Switch]$SkipUnlinked,

        [Parameter(Position = 0, Mandatory = $False)]
        [Alias('p')]
        [String]$Path = $PWD
    )
    begin {
        Write-Verbose -Message '[Get-AzRuleTemplateLink] BEGIN::';

        # Build the pipeline
        $builder = [PSRule.Rules.Azure.Pipeline.PipelineBuilder]::TemplateLink($Path);
        $builder.SkipUnlinked($SkipUnlinked);
        $builder.UseCommandRuntime($PSCmdlet);
        $builder.UseExecutionContext($ExecutionContext);
        $pipeline = $builder.Build();
        if ($Null -ne (Get-Variable -Name pipeline -ErrorAction SilentlyContinue)) {
            try {
                $pipeline.Begin();
            }
            catch {
                $pipeline.Dispose();
                throw;
            }
        }
    }
    process {
        if ($Null -ne (Get-Variable -Name pipeline -ErrorAction SilentlyContinue)) {
            try {
                foreach ($p in $InputPath) {
                    $pipeline.Process($p);
                }
            }
            catch {
                $pipeline.Dispose();
                throw;
            }
        }
    }
    end {
        if ($Null -ne (Get-Variable -Name pipeline -ErrorAction SilentlyContinue)) {
            try {
                $pipeline.End();
            }
            finally {
                $pipeline.Dispose();
            }
        }
        Write-Verbose -Message '[Get-AzRuleTemplateLink] END::';
    }
}

function Export-AzPolicyAssignmentData {
    [CmdletBinding(SupportsShouldProcess = $True, DefaultParameterSetName = 'Default')]
    [OutputType([System.IO.FileInfo])]
    [OutputType([PSObject])]
    param (
        # Name of policy assignment
        [Parameter(ParameterSetName = 'Name', Mandatory = $False)]
        [String]$Name,

        # Fully qualified resource ID of policy assignment
        [Parameter(ParameterSetName = 'Id', Mandatory = $True)]
        [Alias('AssignmentId')]
        [String]$Id,

        # Specifies assignment policy scope
        [Parameter(ParameterSetName = 'Name', Mandatory = $False)]
        [Parameter(ParameterSetName = 'IncludeDescendent', Mandatory = $False)]
        [String]$Scope,

        # Specifies the policy definition ID of the policy assignment
        [Parameter(ParameterSetName = 'Name', Mandatory = $False)]
        [Parameter(ParameterSetName = 'Id', Mandatory = $False)]
        [String]$PolicyDefinitionId,

        # Include all assignments related to given scope
        [Parameter(ParameterSetName = 'IncludeDescendent', Mandatory = $True)]
        [Switch]$IncludeDescendent = $False,

        [Parameter(Mandatory = $False)]
        [String]$OutputPath = $PWD,

        [Parameter(Mandatory = $False)]
        [Switch]$PassThru = $False
    )
    begin {
        Write-Verbose -Message '[Export-AzPolicyAssignmentData] BEGIN::';
    }
    process {
        $context = GetAzureContext -ErrorAction SilentlyContinue

        if ($Null -eq $context) {
            Write-Error -Message 'Could not find an existing context. Use Connect-AzAccount to establish a PowerShell context with Azure.';
            return;
        }

        if (!(Test-Path -Path $OutputPath)) {
            if ($PSCmdlet.ShouldProcess('Create output directory', $OutputPath)) {
                $Null = New-Item -Path $OutputPath -ItemType Directory -Force;
            }
        }

        $getParams = @{ };

        Write-Verbose -Message "Parameter Set: $($PSCmdlet.ParameterSetName)";

        if ($PSCmdlet.ParameterSetName -eq 'Name') {
            if ($PSBoundParameters.ContainsKey('Name')) {
                $getParams['Name'] = $Name;
            }

            if ($PSBoundParameters.ContainsKey('PolicyDefinitionId')) {
                $getParams['PolicyDefinitionId'] = $PolicyDefinitionId;
            }
    
            if ($PSBoundParameters.ContainsKey('Scope')) {
                $getParams['Scope'] = $Scope;
            }
            else {
                $getParams['Scope'] = GetDefaultSubscriptionScope -Context $context
            }

            Write-Verbose -Message "Scope: $($getParams['Scope'])";
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'Id') {
            $getParams['Id'] = $Id;

            if ($PSBoundParameters.ContainsKey('PolicyDefinitionId')) {
                $getParams['PolicyDefinitionId'] = $PolicyDefinitionId;
            }
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'IncludeDescendent') {
            $getParams['IncludeDescendent'] = $IncludeDescendent;

            if ($PSBoundParameters.ContainsKey('Scope')) {
                $getParams['Scope'] = $Scope;
            }
            else {
                $getParams['Scope'] = GetDefaultSubscriptionScope -Context $context
            }
        }

        Write-Verbose -Message "[Export] -- Using subscription: $($context.Subscription.Name)";
        $filePath = Join-Path -Path $OutputPath -ChildPath "$($context.Subscription.Id).assignment.json";
        Get-AzPolicyAssignment @getParams -Verbose:$VerbosePreference `
        | ExpandPolicyAssignment -Context $context -Verbose:$VerbosePreference `
        | ExportAzureResource -Path $filePath -PassThru $PassThru -Verbose:$VerbosePreference;
    }
    end {
        Write-Verbose -Message "[Export-AzPolicyAssignmentData] END::";
    }
}

function Export-AzPolicyAssignmentRuleData {
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    [OutputType([System.IO.FileInfo])]
    [OutputType([PSObject])]
    param (
        # Name of Policy assignment
        [Parameter(Mandatory = $False)]
        [String]$Name,

        # Assignment file path
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]$AssignmentFile,

        [Parameter(Mandatory = $False)]
        [Alias('ResourceGroupName')]
        [PSRule.Rules.Azure.Configuration.ResourceGroupReference]$ResourceGroup,

        [Parameter(Mandatory = $False)]
        [PSRule.Rules.Azure.Configuration.SubscriptionReference]$Subscription,

        [Parameter(Mandatory = $False)]
        [String]$OutputPath = $PWD,

        [Parameter(Mandatory = $False)]
        [String]$RulePrefix,

        [Parameter(Mandatory = $False)]
        [Switch]$PassThru = $False
    )
    begin {
        Write-Verbose -Message '[Export-AzPolicyAssignmentRuleData] BEGIN::';

        $option = [PSRule.Rules.Azure.Configuration.PSRuleOption]::FromFileOrDefault($PWD);
        $option.Output.Path = $OutputPath;

        if ($PSBoundParameters.ContainsKey('RulePrefix')) {
            $option.Configuration.PolicyRulePrefix = $RulePrefix
        }

        # Build the pipeline
        $builder = [PSRule.Rules.Azure.Pipeline.PipelineBuilder]::Assignment($option);
        $builder.Assignment($Name);
        $builder.PassThru($PassThru);

        # Bind to subscription context
        if ($PSBoundParameters.ContainsKey('Subscription')) {
            $subscriptionOption = GetSubscription -InputObject $Subscription -ErrorAction SilentlyContinue;
            if ($Null -ne $subscriptionOption) {
                $builder.Subscription($subscriptionOption);
            }
        }
        # Bind to resource group
        if ($PSBoundParameters.ContainsKey('ResourceGroup')) {
            $resourceGroupOption = GetResourceGroup -InputObject $ResourceGroup -ErrorAction SilentlyContinue;
            if ($Null -ne $resourceGroupOption) {
                $builder.ResourceGroup($resourceGroupOption);
            }
        }

        $builder.UseCommandRuntime($PSCmdlet);
        $builder.UseExecutionContext($ExecutionContext);
        try {
            $pipeline = $builder.Build();
            $pipeline.Begin();
        }
        catch {
            $pipeline.Dispose();
        }
    }
    process {
        if ($Null -ne (Get-Variable -Name pipeline -ErrorAction SilentlyContinue)) {
            try {
                $source = [PSRule.Rules.Azure.Pipeline.PolicyAssignmentSource]::new($AssignmentFile);
                $pipeline.Process($source);
            }
            catch {
                $pipeline.Dispose();
                throw;
            }
        }
    }
    end {
        if ($Null -ne (Get-Variable -Name pipeline -ErrorAction SilentlyContinue)) {
            try {
                $pipeline.End();
            }
            finally {
                $pipeline.Dispose();
            }
        }
        Write-Verbose -Message '[Export-AzPolicyAssignmentRuleData] END::';
    }
}

function Get-AzPolicyAssignmentDataSource {
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    [OutputType([PSRule.Rules.Azure.Pipeline.PolicyAssignmentSource])]
    param (
        [Parameter(Mandatory = $False, ValueFromPipelineByPropertyName = $True)]
        [Alias('f', 'AssignmentFile', 'FullName')]
        [SupportsWildcards()]
        [String[]]$InputPath = '*.assignment.json',

        [Parameter(Mandatory = $False)]
        [Alias('p')]
        [String]$Path = $PWD
    )
    begin {
        Write-Verbose -Message '[Get-AzPolicyAssignmentDataSource] BEGIN::';

        # Build the pipeline
        $builder = [PSRule.Rules.Azure.Pipeline.PipelineBuilder]::AssignmentSearch($Path);
        $builder.UseCommandRuntime($PSCmdlet);
        $builder.UseExecutionContext($ExecutionContext);
        $pipeline = $builder.Build();
        if ($Null -ne (Get-Variable -Name pipeline -ErrorAction SilentlyContinue)) {
            try {
                $pipeline.Begin();
            }
            catch {
                $pipeline.Dispose();
                throw;
            }
        }
    }
    process {
        if ($Null -ne (Get-Variable -Name pipeline -ErrorAction SilentlyContinue)) {
            try {
                foreach ($p in $InputPath) {
                    $pipeline.Process($p);
                }
            }
            catch {
                $pipeline.Dispose();
                throw;
            }
        }
    }
    end {
        if ($Null -ne (Get-Variable -Name pipeline -ErrorAction SilentlyContinue)) {
            try {
                $pipeline.End();
            }
            finally {
                $pipeline.Dispose();
            }
        }
        Write-Verbose -Message '[Get-AzPolicyAssignmentDataSource] END::';
    }
}

#endregion Public functions

#
# Helper functions
#

function GetDefaultSubscriptionScope {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.Core.IAzureContextContainer]$Context
    )
    process {
        return [string]::Concat('/subscriptions/', $context.Subscription.Id);
    }
}

function GetResourceGroup {
    [CmdletBinding()]
    [OutputType([PSRule.Rules.Azure.Configuration.ResourceGroupOption])]
    param (
        [Parameter(Mandatory = $True)]
        [PSRule.Rules.Azure.Configuration.ResourceGroupReference]$InputObject
    )
    process {
        $result = $InputObject.ToResourceGroupOption();
        if ($InputObject.FromName) {
            $o = Get-AzResourceGroup -Name $InputObject.Name -ErrorAction SilentlyContinue;
            if ($Null -ne $o) {
                $result.Name = $o.ResourceGroupName
                $result.Location = $o.Location
                $result.ManagedBy = $o.ManagedBy
                $result.Properties.ProvisioningState = $o.ProvisioningState
                $result.Tags = $o.Tags
            }
        }
        return $result;
    }
}

function GetSubscription {
    [CmdletBinding()]
    [OutputType([PSRule.Rules.Azure.Configuration.SubscriptionOption])]
    param (
        [Parameter(Mandatory = $True)]
        [PSRule.Rules.Azure.Configuration.SubscriptionReference]$InputObject
    )
    process {
        $result = $InputObject.ToSubscriptionOption();
        if ($InputObject.FromName) {
            $o = (Set-AzContext -Subscription $InputObject.DisplayName -ErrorAction SilentlyContinue).Subscription;
            if ($Null -ne $o) {
                $result.DisplayName = $o.Name
                $result.SubscriptionId = $o.SubscriptionId
                $result.State = $o.State
                $result.TenantId = $o.TenantId
            }
        }
        return $result;
    }
}

function FindAzureContext {
    [CmdletBinding()]
    [OutputType([Microsoft.Azure.Commands.Common.Authentication.Abstractions.Core.IAzureContextContainer[]])]
    param (
        [Parameter(Mandatory = $False)]
        [String[]]$Subscription = $Null,

        [Parameter(Mandatory = $False)]
        [String[]]$Tenant = $Null,

        [Parameter(Mandatory = $False)]
        [System.Boolean]$All = $False
    )
    process {
        $listAvailable = $False;
        if ($Null -ne $Subscription -or $Null -ne $Tenant -or $All) {
            $listAvailable = $True;
        }

        # Get subscription contexts
        $context = @(GetAzureContext -ListAvailable:$listAvailable);
        if ($Null -eq $context -and $context.Length -gt 0) {
            Write-Error -Message 'Could not find an existing context. Use Connect-AzAccount to establish a PowerShell context with Azure.';
            return;
        }

        Write-Verbose "[Context] -- Found ($($context.Length)) subscription contexts";
        $filteredContext = @($context | ForEach-Object -Process {
                if (
                ($Null -eq $Tenant -or $Tenant.Length -eq 0 -or ($_.Tenant.Id -in $Tenant)) -and
                ($Null -eq $Subscription -or $Subscription.Length -eq 0 -or ($_.Subscription.Id -in $Subscription) -or ($_.Subscription.Name -in $Subscription))
                ) {
                    $_;
                    Write-Verbose "[Context] -- Using subscription: $($_.Subscription.Name)";
                }
            })
        Write-Verbose "[Context] -- Using [$($filteredContext.Length)/$($context.Length)] subscription contexts";
        return $filteredContext;
    }
}

function GetAzureContext {
    [CmdletBinding()]
    [OutputType([Microsoft.Azure.Commands.Common.Authentication.Abstractions.Core.IAzureContextContainer[]])]
    param (
        [Parameter(Mandatory = $False)]
        [System.Boolean]$ListAvailable = $False
    )
    process {
        $getParams = @{ };
        if ($ListAvailable) {
            $getParams['ListAvailable'] = $True;
        }

        # Get contexts
        return Get-AzContext @getParams;
    }
}

function GetAzureResource {
    [CmdletBinding()]
    [OutputType([PSObject])]
    param (
        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.Core.IAzureContextContainer]$Context,

        [Parameter(Mandatory = $False)]
        [Hashtable]$Tag,

        [Parameter(Mandatory = $False)]
        [String[]]$ResourceGroupName = $Null
    )
    begin {
        $watch = New-Object -TypeName System.Diagnostics.Stopwatch;
    }
    process {
        $resourceParams = @{ };
        $rgParams = @{ };

        if ($PSBoundParameters.ContainsKey('Tag')) {
            $resourceParams['Tag'] = $Tag;
            $rgParams['Tag'] = $Tag;
        }

        try {
            Write-Verbose -Message "[Export] -- Getting Azure resources";
            $watch.Restart();

            if ($PSBoundParameters.ContainsKey('ResourceGroupName')) {
                foreach ($rg in $ResourceGroupName) {
                    Write-Verbose -Message "[Export] -- Getting Azure resources for Resource Group: $rg";
                    Get-AzResource @resourceParams -ResourceGroupName $rg -ExpandProperties -ODataQuery "SubscriptionId EQ '$($Context.DefaultContext.Subscription.Id)'" -DefaultProfile $Context `
                    | ExpandResource -Context $Context -Verbose:$VerbosePreference;
                    Get-AzResourceGroup @rgParams -Name $rg -DefaultProfile $Context |
                    SetResourceType 'Microsoft.Resources/resourceGroups' |
                    ExpandResource -Context $Context -Verbose:$VerbosePreference;
                }
            }
            else {
                Get-AzResource @resourceParams -ExpandProperties -DefaultProfile $Context |
                ExpandResource -Context $Context -Verbose:$VerbosePreference;
                Get-AzResourceGroup @rgParams -DefaultProfile $Context |
                SetResourceType 'Microsoft.Resources/resourceGroups' |
                ExpandResource -Context $Context -Verbose:$VerbosePreference;
            }

            Write-Verbose -Message "[Export] -- Azure resources exported in [$($watch.ElapsedMilliseconds) ms]";
            $watch.Restart();

            Write-Verbose -Message "[Export] -- Getting Azure subscription: $($Context.DefaultContext.Subscription.Id)";
            Get-AzSubscription -SubscriptionId $Context.DefaultContext.Subscription.Id |
            SetResourceType 'Microsoft.Subscription' |
            ExpandResource -Context $Context -Verbose:$VerbosePreference;

            Write-Verbose -Message "[Export] -- Azure subscription exported in [$($watch.ElapsedMilliseconds) ms]";
        }
        finally {
            $watch.Stop();
        }
    }
}

function FilterAzureResource {
    [CmdletBinding()]
    [OutputType([PSObject])]
    param (
        [Parameter(Mandatory = $False)]
        [String[]]$ResourceGroupName = $Null,

        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject]$InputObject
    )
    process {
        if (($Null -eq $ResourceGroupName) -or ($InputObject.ResourceType -eq 'Microsoft.Subscription') -or (@($InputObject.PSObject.Properties | Where-Object { $_.Name -eq 'ResourceGroupName' }).Length -eq 0)) {
            return $InputObject;
        }
        elseif ($InputObject.ResourceGroupName -in $ResourceGroupName) {
            return $InputObject;
        }
    }
}

function ExportAzureResource {
    [CmdletBinding(SupportsShouldProcess = $True)]
    [OutputType([System.IO.FileInfo])]
    [OutputType([PSObject])]
    param (
        [Parameter(Mandatory = $True)]
        [String]$Path,

        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject]$InputObject,

        [Parameter(Mandatory = $False)]
        [System.Boolean]$PassThru = $False
    )
    begin {
        $resources = @();
    }
    process {
        if ($PassThru) {
            $InputObject;
        }
        else {
            # Collect passed through resources
            $resources += $InputObject;
        }
    }
    end {
        $watch = New-Object -TypeName System.Diagnostics.Stopwatch;
        Write-Verbose -Message "[Export] -- Exporting to JSON";
        $watch.Restart();

        if (!$PassThru) {
            # Save to JSON
            ConvertTo-Json -InputObject $resources -Depth 100 | Set-Content -Path $Path;
            Get-Item -Path $Path;
        }
        $watch.Stop();
        Write-Verbose -Message "[Export] -- Exported to JSON in [$($watch.ElapsedMilliseconds) ms]";
    }
}

function GetSubResource {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [PSObject]$Resource,

        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.Core.IAzureContextContainer]$Context,

        [Parameter(Mandatory = $True)]
        [String]$ResourceType,

        [Parameter(Mandatory = $True)]
        [String]$ApiVersion
    )
    process {
        $getParams = @{
            Name              = $Resource.Name
            ResourceType      = $ResourceType
            ResourceGroupName = $Resource.ResourceGroupName
            DefaultProfile    = $Context
            ApiVersion        = $ApiVersion
        }
        try {
            Get-AzResource @getParams -ExpandProperties;
        }
        catch {
            Write-Warning -Message "Failed to read $($Resource.Name): $ResourceType";
        }
    }
}

function GetResourceById {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [PSObject]$ResourceId,

        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.Core.IAzureContextContainer]$Context,

        [Parameter(Mandatory = $True)]
        [String]$ApiVersion
    )
    process {
        $getParams = @{
            ResourceId     = $ResourceId
            DefaultProfile = $Context
            ApiVersion     = $ApiVersion
        }
        try {
            Get-AzResource @getParams -ExpandProperties;
        }
        catch {
            Write-Warning -Message "Failed to read $ResourceId";
        }
    }
}

function GetSubResourceId {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [PSObject]$Resource,

        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.Core.IAzureContextContainer]$Context,

        [Parameter(Mandatory = $True)]
        [String]$Property,

        [Parameter(Mandatory = $True)]
        [String]$ApiVersion
    )
    process {
        $getParams = @{
            ResourceId     = [String]::Concat($Resource.Id, '/', $Property)
            DefaultProfile = $Context
            ApiVersion     = $ApiVersion
        }
        try {
            Get-AzResource @getParams -ExpandProperties;
        }
        catch {
            Write-Warning -Message "Failed to read $($Resource.Name): $Property";
        }
    }
}

function GetRestProperty {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [PSObject]$Resource,

        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.Core.IAzureContextContainer]$Context,

        [Parameter(Mandatory = $True)]
        [String]$Property,

        [Parameter(Mandatory = $True)]
        [String]$ApiVersion
    )
    process {
        try {
            $token = GetRestToken -Context $Context;
            $getParams = @{
                Uri     = [String]::Concat('https://management.azure.com', $Resource.Id, '/', $Property, '?api-version=', $ApiVersion)
                Headers = @{
                    Authorization = "Bearer $($token)"
                }
            }
            Invoke-RestMethod -Method Get @getParams -UseBasicParsing -Verbose:$VerbosePreference;
        }
        catch {
            Write-Warning -Message "Failed to read $($Resource.Name): $Property";
        }
    }
}

function GetRestToken {
    [CmdletBinding()]
    [OutputType([String])]
    param (
        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.Core.IAzureContextContainer]$Context
    )
    process {
        return ($Context.DefaultContext.TokenCache.ReadItems() | Where-Object {
                $_.TenantId -eq $Context.DefaultContext.Tenant.Id -and
                $_.Resource -eq 'https://management.core.windows.net/' -and
                $_.Authority -eq "https://login.windows.net/$($Context.DefaultContext.Tenant.Id)/"
            }).AccessToken;
    }
}

function GetSubProvider {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [PSObject]$Resource,

        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.Core.IAzureContextContainer]$Context,

        [Parameter(Mandatory = $True)]
        [String]$ResourceType,

        [Parameter(Mandatory = $True)]
        [String]$ApiVersion,

        [Parameter(Mandatory = $False)]
        [Switch]$ExpandProperties
    )
    process {
        $getParams = @{
            ResourceId     = [String]::Concat($Resource.Id, '/providers/', $ResourceType)
            DefaultProfile = $Context
            ApiVersion     = $ApiVersion
        }
        try {
            Get-AzResource @getParams -ExpandProperties:$ExpandProperties;
        }
        catch {
            Write-Warning -Message "Failed to read $($Resource.Name): $ResourceType";
        }
    }
}

function VisitAPIManagement {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject]$Resource,

        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.Core.IAzureContextContainer]$Context
    )
    process {
        $resources = @();
        $apis += GetSubResource @PSBoundParameters -ResourceType 'Microsoft.ApiManagement/service/apis' -ApiVersion '2019-12-01';
        foreach ($api in $apis) {
            $resources += $api;
            $apiParams = @{
                Name              = "$($Resource.Name)/$($api.Name)"
                ResourceType      = 'Microsoft.ApiManagement/service/apis/policies'
                ResourceGroupName = $Resource.ResourceGroupName
                DefaultProfile    = $Context
                ApiVersion        = '2019-12-01'
            };
            $resources += Get-AzResource @apiParams;
        }

        # Add zones in from REST API because they are not included from Get-AzResource
        $apiManagementServicePrimaryZones = ((Invoke-AzRestMethod -Path "$($Resource.ResourceId)?api-version=2020-12-01" -Method GET).Content | ConvertFrom-Json).zones;
        $Resource = $Resource | Add-Member -MemberType NoteProperty -Name zones -Value $apiManagementServicePrimaryZones -PassThru;

        $resources += GetSubResource @PSBoundParameters -ResourceType 'Microsoft.ApiManagement/service/backends' -ApiVersion '2019-12-01';
        $resources += GetSubResource @PSBoundParameters -ResourceType 'Microsoft.ApiManagement/service/products' -ApiVersion '2019-12-01';
        $resources += GetSubResource @PSBoundParameters -ResourceType 'Microsoft.ApiManagement/service/policies' -ApiVersion '2019-12-01';
        $resources += GetSubResource @PSBoundParameters -ResourceType 'Microsoft.ApiManagement/service/identityProviders' -ApiVersion '2019-12-01';
        $resources += GetSubResource @PSBoundParameters -ResourceType 'Microsoft.ApiManagement/service/diagnostics' -ApiVersion '2019-12-01';
        $resources += GetSubResource @PSBoundParameters -ResourceType 'Microsoft.ApiManagement/service/loggers' -ApiVersion '2019-12-01';
        $resources += GetSubResource @PSBoundParameters -ResourceType 'Microsoft.ApiManagement/service/certificates' -ApiVersion '2019-12-01';
        $resources += GetSubResource @PSBoundParameters -ResourceType 'Microsoft.ApiManagement/service/namedValues' -ApiVersion '2019-12-01';
        $resources += GetSubResource @PSBoundParameters -ResourceType 'Microsoft.ApiManagement/service/portalsettings' -ApiVersion '2019-12-01';
        $Resource | Add-Member -MemberType NoteProperty -Name resources -Value $resources -PassThru;
    }
}

function VisitSqlServer {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject]$Resource,

        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.Core.IAzureContextContainer]$Context
    )
    process {
        $sqlServer = $resource;
        $resources = @();

        # Get SQL Server firewall rules
        $resources += GetSubResource @PSBoundParameters -ResourceType 'Microsoft.Sql/servers/firewallRules' -ApiVersion '2015-05-01-preview';
        $resources += GetSubResource @PSBoundParameters -ResourceType 'Microsoft.Sql/servers/administrators' -ApiVersion '2014-04-01';
        $resources += GetSubResource @PSBoundParameters -ResourceType 'Microsoft.Sql/servers/securityAlertPolicies' -ApiVersion '2017-03-01-preview';
        $resources += GetSubResource @PSBoundParameters -ResourceType 'Microsoft.Sql/servers/vulnerabilityAssessments' -ApiVersion '2018-06-01-preview';
        $resources += GetSubResource @PSBoundParameters -ResourceType 'Microsoft.Sql/servers/auditingSettings' -ApiVersion '2017-03-01-preview';
        $sqlServer | Add-Member -MemberType NoteProperty -Name resources -Value $resources -PassThru;
    }
}

function VisitSqlDatabase {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject]$Resource,

        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.Core.IAzureContextContainer]$Context
    )
    process {
        $resources = @();
        $getParams = @{
            ResourceGroupName = $Resource.ResourceGroupName
            DefaultProfile    = $Context
            ErrorAction       = 'SilentlyContinue'
        }
        $idParts = $Resource.ResourceId.Split('/');
        $serverName = $idParts[-3];
        $resourceName = "$serverName/$($Resource.Name)";
        $resources += Get-AzResource @getParams -Name $resourceName -ResourceType 'Microsoft.Sql/servers/databases/dataMaskingPolicies' -ApiVersion '2014-04-01' -ExpandProperties
        $resources += Get-AzResource @getParams -Name $resourceName -ResourceType 'Microsoft.Sql/servers/databases/transparentDataEncryption' -ApiVersion '2014-04-01' -ExpandProperties;
        $resources += Get-AzResource @getParams -Name $resourceName -ResourceType 'Microsoft.Sql/servers/databases/connectionPolicies' -ApiVersion '2014-04-01' -ExpandProperties;
        $resources += Get-AzResource @getParams -Name $resourceName -ResourceType 'Microsoft.Sql/servers/databases/geoBackupPolicies' -ApiVersion '2014-04-01' -ExpandProperties;
        $Resource | Add-Member -MemberType NoteProperty -Name resources -Value $resources -PassThru;
    }
}

function VisitPostgreSqlServer {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject]$Resource,

        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.Core.IAzureContextContainer]$Context
    )
    process {
        $sqlServer = $resource;
        $resources = @();

        # Get Postgre SQL Server firewall rules
        $resources += GetSubResource @PSBoundParameters -ResourceType 'Microsoft.DBforPostgreSQL/servers/firewallRules' -ApiVersion '2017-12-01';
        $resources += GetSubResource @PSBoundParameters -ResourceType 'Microsoft.DBforPostgreSQL/servers/securityAlertPolicies' -ApiVersion '2017-12-01';
        $resources += GetSubResource @PSBoundParameters -ResourceType 'Microsoft.DBforPostgreSQL/servers/configurations' -ApiVersion '2017-12-01';
        $sqlServer | Add-Member -MemberType NoteProperty -Name resources -Value $resources -PassThru;
    }
}

function VisitMySqlServer {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject]$Resource,

        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.Core.IAzureContextContainer]$Context
    )
    process {
        $sqlServer = $resource;
        $resources = @();

        # Get MySQL Server firewall rules
        $resources += GetSubResource @PSBoundParameters -ResourceType 'Microsoft.DBforMySQL/servers/firewallRules' -ApiVersion '2017-12-01';
        $resources += GetSubResource @PSBoundParameters -ResourceType 'Microsoft.DBforMySQL/servers/securityAlertPolicies' -ApiVersion '2017-12-01';
        $resources += GetSubResource @PSBoundParameters -ResourceType 'Microsoft.DBforMySQL/servers/configurations' -ApiVersion '2017-12-01';
        $sqlServer | Add-Member -MemberType NoteProperty -Name resources -Value $resources -PassThru;
    }
}

function VisitSqlManagedInstance {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject]$Resource,

        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.Core.IAzureContextContainer]$Context
    )
    process {
        $sqlMI = $resource;
        $resources = @();

        $resources += Get-AzResource -Name $resource.Name -ResourceType 'Microsoft.Sql/managedInstances/securityAlertPolicies' -ResourceGroupName $resource.ResourceGroupName -DefaultProfile $Context -ApiVersion '2017-03-01-preview' -ExpandProperties;
        $resources += Get-AzResource -Name $resource.Name -ResourceType 'Microsoft.Sql/managedInstances/vulnerabilityAssessments' -ResourceGroupName $resource.ResourceGroupName -DefaultProfile $Context -ApiVersion '2018-06-01-preview' -ExpandProperties;
        $resources += Get-AzResource -Name $resource.Name -ResourceType 'Microsoft.Sql/managedInstances/administrators' -ResourceGroupName $resource.ResourceGroupName -DefaultProfile $Context -ApiVersion '2017-03-01-preview' -ExpandProperties;
        $sqlMI | Add-Member -MemberType NoteProperty -Name resources -Value $resources -PassThru;
    }
}

function VisitAutomationAccount {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject]$Resource,

        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.Core.IAzureContextContainer]$Context
    )
    process {
        $aa = $Resource
        $resources = @();
        $resources += GetSubResource @PSBoundParameters -ResourceType 'Microsoft.Automation/AutomationAccounts/variables' -ApiVersion '2015-10-31';
        $resources += GetSubResource @PSBoundParameters -ResourceType 'Microsoft.Automation/AutomationAccounts/webhooks' -ApiVersion '2015-10-31';

        $diagnosticSettingsResourceParams = @{
            Name              = $Resource.Name
            ResourceType      = 'Microsoft.Automation/automationAccounts/providers/microsoft.insights/diagnosticSettings'
            ResourceGroupName = $Resource.ResourceGroupName
            DefaultProfile    = $Context
            ExpandProperties  = $True
            ApiVersion        = '2021-05-01-preview'
        }

        $resources += Get-AzResource @diagnosticSettingsResourceParams

        $aa | Add-Member -MemberType NoteProperty -Name resources -Value $resources -PassThru;
    }
}

# function VisitDataFactoryV2 {
#     param (
#         [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
#         [PSObject]$Resource,

#         [Parameter(Mandatory = $True)]
#         [Microsoft.Azure.Commands.Common.Authentication.Abstractions.Core.IAzureContextContainer]$Context
#     )
#     process {
#         $df = $resource;
#         $resources = @();

#         # Get linked services
#         $resources += Get-AzDataFactoryV2LinkedService -DataFactoryName $resource.Name -ResourceGroupName $resource.ResourceGroupName -DefaultProfile $Context | ForEach-Object -Process {
#             $linkedService = $_;
#             $type = $linkedService.Properties.GetType().Name;
#             $linkedService.Properties.AdditionalProperties = $Null;
#             if ($Null -ne $linkedService.Properties.EncryptedCredential) {
#                 $linkedService.Properties.EncryptedCredential = $Null;
#             }

#             $linkedService | Add-Member -MemberType NoteProperty -Name 'ResourceType' -Value 'linkedServices';
#             $linkedService | Add-Member -MemberType NoteProperty -Name 'Type' -Value $type;
#             $linkedService;
#         };
#         $df | Add-Member -MemberType NoteProperty -Name resources -Value $resources -PassThru;
#     }
# }

function VisitCDNEndpoint {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject]$Resource,

        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.Core.IAzureContextContainer]$Context
    )
    process {
        $resources = @();
        $resources += GetSubResourceId @PSBoundParameters -Property 'customdomains' -ApiVersion '2019-04-15';
        $Resource | Add-Member -MemberType NoteProperty -Name resources -Value $resources -PassThru;
    }
}

function VisitContainerRegistry {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject]$Resource,

        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.Core.IAzureContextContainer]$Context
    )
    process {
        $resources = @();
        $resources += GetSubResource @PSBoundParameters -ResourceType 'Microsoft.ContainerRegistry/registries/replications' -ApiVersion '2019-12-01-preview';
        $resources += GetSubResource @PSBoundParameters -ResourceType 'Microsoft.ContainerRegistry/registries/webhooks' -ApiVersion '2019-12-01-preview';
        $resources += GetSubResource @PSBoundParameters -ResourceType 'Microsoft.ContainerRegistry/registries/tasks' -ApiVersion '2019-06-01-preview';
        $resources += GetRestProperty @PSBoundParameters -Property 'listUsages' -ApiVersion '2019-05-01' | SetResourceType 'Microsoft.ContainerRegistry/registries/listUsages';
        $resources += GetSubProvider @PSBoundParameters -ResourceType 'Microsoft.Security/assessments' -ApiVersion '2019-01-01-preview';
        $Resource | Add-Member -MemberType NoteProperty -Name resources -Value $resources -PassThru;
    }
}

function VisitAKSCluster {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject]$Resource,

        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.Core.IAzureContextContainer]$Context
    )
    process {
        $resources = @();

        # Only add VNET resource if AKS cluster is using Azure CNI network plugin
        # Supported network plugins: azure or kubenet
        # https://docs.microsoft.com/en-us/azure/templates/microsoft.containerservice/managedclusters?tabs=json#containerservicenetworkprofile-object
        if ($Resource.Properties.networkProfile.networkPlugin -eq 'azure') {
            $nodePools = @($Resource.Properties.agentPoolProfiles);
            foreach ($nodePool in $nodePools) {
                $vnetId = $nodePool.vnetSubnetID;
                $resources += GetResourceById -ResourceId $vnetId -ApiVersion '2020-05-01' -Context $Context;
            }
        }

        $resources += Get-AzResource -Name $Resource.Name -ResourceType 'Microsoft.ContainerService/managedClusters/providers/microsoft.insights/diagnosticSettings' -ResourceGroupName $Resource.ResourceGroupName -DefaultProfile $Context -ApiVersion '2017-05-01-preview' -ExpandProperties;

        $Resource | Add-Member -MemberType NoteProperty -Name resources -Value $resources -PassThru;
    }
}

function VisitPublicIP {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject]$Resource,

        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.Core.IAzureContextContainer]$Context
    )
    process {
        # Get-AzResource does not return zones, even with latest API version
        # Had to fetch the zones using ARM REST API and insert them into the resource
        # Logged an issue with Az PowerShell: https://github.com/Azure/azure-powershell/issues/15905
        $publicIp = ((Invoke-AzRestMethod -Path "$($Resource.ResourceId)?api-version=2021-02-01" -Method GET).Content | ConvertFrom-Json).PSObject.Properties['zones'];
        if ($Null -ne $publicIp) {
            $Resource | Add-Member -MemberType NoteProperty -Name zones -Value $publicIp.value -PassThru;
        }
        else {
            $Resource;
        }
    }
}

function VisitRedisCache {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject]$Resource,

        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.Core.IAzureContextContainer]$Context
    )
    process {
        # Get-AzResource does not return zones, even with latest API version
        # Had to fetch the zones using ARM REST API and insert them into the resource
        # Logged an issue with Az PowerShell: https://github.com/Azure/azure-powershell/issues/15905
        $redisCacheZones = ((Invoke-AzRestMethod -Path "$($Resource.ResourceId)?api-version=2021-06-01" -Method GET).Content | ConvertFrom-Json).PSObject.Properties['zones'];
        if ($Null -ne $redisCacheZones) {
            $Resource | Add-Member -MemberType NoteProperty -Name zones -Value $redisCacheZones.value -PassThru;
        }
        else {
            $Resource;
        }
    }
}

function VisitRedisEnterpriseCache {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject]$Resource,

        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.Core.IAzureContextContainer]$Context
    )
    process {
        # Get-AzResource does not return zones, even with latest API version
        # Had to fetch the zones using ARM REST API and insert them into the resource
        # Logged an issue with Az PowerShell: https://github.com/Azure/azure-powershell/issues/15905
        $redisEnterpriseCacheZones = ((Invoke-AzRestMethod -Path "$($Resource.ResourceId)?api-version=2021-08-01" -Method GET).Content | ConvertFrom-Json).PSObject.Properties['zones'];
        if ($Null -ne $redisEnterpriseCacheZones) {
            $Resource | Add-Member -MemberType NoteProperty -Name zones -Value $redisEnterpriseCacheZones.value -PassThru;
        }
        else {
            $Resource;
        }
    }
}

function VisitStorageAccount {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject]$Resource,

        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.Core.IAzureContextContainer]$Context
    )
    process {
        $resources = @();
        if ($Resource.Kind -ne 'FileStorage') {
            $blobServices = @(GetSubResource @PSBoundParameters -ResourceType 'Microsoft.Storage/storageAccounts/blobServices' -ApiVersion '2019-04-01');
            foreach ($blobService in $blobServices) {
                $resources += $blobService;
                $resources += Get-AzResource -Name "$($Resource.Name)/$($blobService.Name)" -ResourceType 'Microsoft.Storage/storageAccounts/blobServices/containers' -ResourceGroupName $Resource.ResourceGroupName -DefaultProfile $Context -ApiVersion '2019-04-01' -ExpandProperties;
            }
        }
        $Resource | Add-Member -MemberType NoteProperty -Name resources -Value $resources -PassThru;
    }
}

function VisitStorageSyncService {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject]$Resource,

        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.Core.IAzureContextContainer]$Context
    )
    process {
        $resources = @();
        $resources += Get-AzStorageSyncServer -ParentResourceId $Resource.ResourceId -DefaultProfile $Context;
        $Resource | Add-Member -MemberType NoteProperty -Name resources -Value $resources -PassThru;
    }
}

function VisitWebApp {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject]$Resource,

        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.Core.IAzureContextContainer]$Context
    )
    process {
        $resources = @();
        $configResourceType = 'Microsoft.Web/sites/config';

        # Handle slots
        if ($Resource.ResourceType -eq 'Microsoft.Web/sites/slots') {
            $configResourceType = 'Microsoft.Web/sites/slots/config';
        }

        $resources += Get-AzResource -Name $Resource.Name -ResourceType $configResourceType -ResourceGroupName $Resource.ResourceGroupName -DefaultProfile $Context -ApiVersion '2018-11-01' -ExpandProperties;
        $Resource | Add-Member -MemberType NoteProperty -Name resources -Value $resources -PassThru;
    }
}

function VisitRecoveryServices {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject]$Resource,

        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.Core.IAzureContextContainer]$Context
    )
    process {
        $resources = @();
        $resources += Get-AzResource -Name $resource.Name -ResourceType 'Microsoft.RecoveryServices/vaults/replicationRecoveryPlans' -ResourceGroupName $resource.ResourceGroupName -DefaultProfile $Context -ApiVersion '2018-07-10' -ExpandProperties;
        $resources += Get-AzResource -Name $resource.Name -ResourceType 'Microsoft.RecoveryServices/vaults/replicationAlertSettings' -ResourceGroupName $resource.ResourceGroupName -DefaultProfile $Context -ApiVersion '2018-07-10' -ExpandProperties;
        $resources += Get-AzResource -Name $resource.Name -ResourceType 'Microsoft.RecoveryServices/vaults/backupstorageconfig/vaultstorageconfig' -ResourceGroupName $resource.ResourceGroupName -DefaultProfile $Context -ApiVersion '2018-07-10' -ExpandProperties;
        $Resource | Add-Member -MemberType NoteProperty -Name resources -Value $resources -PassThru;
    }
}

function VisitVirtualMachine {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject]$Resource,

        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.Core.IAzureContextContainer]$Context
    )
    process {
        $resources = @();
        $networkInterfaceId = $Resource.Properties.networkProfile.networkInterfaces.id;
        foreach ($id in $networkInterfaceId) {
            $resources += Get-AzResource -ResourceId $id -ExpandProperties -DefaultProfile $Context;
        }
        $Resource | Add-Member -MemberType NoteProperty -Name resources -Value $resources -PassThru;
    }
}

function VisitKeyVault {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject]$Resource,

        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.Core.IAzureContextContainer]$Context
    )
    process {
        $resources = @();
        $resources += Get-AzResource -Name $resource.Name -ResourceType 'Microsoft.KeyVault/vaults/providers/microsoft.insights/diagnosticSettings' -ResourceGroupName $resource.ResourceGroupName -DefaultProfile $Context -ApiVersion '2017-05-01-preview' -ExpandProperties;

        $resources += GetResourceById -ResourceId "$($Resource.Id)/keys" -Context $Context -ApiVersion '2021-11-01-preview';

        $Resource | Add-Member -MemberType NoteProperty -Name resources -Value $resources -PassThru;
    }
}

function VisitFrontDoor {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject]$Resource,

        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.Core.IAzureContextContainer]$Context
    )
    process {
        # Patch Front Door properties not fully returned from the default API version
        $Resource = Get-AzResource -Name $resource.Name -ResourceGroupName $resource.ResourceGroupName -DefaultProfile $Context -ResourceType 'Microsoft.Network/frontdoors' -ExpandProperties -ApiVersion '2018-08-01';

        $resources = @();
        $resources += Get-AzResource -Name $resource.Name -ResourceType 'Microsoft.Network/frontdoors/providers/microsoft.insights/diagnosticSettings' -ResourceGroupName $resource.ResourceGroupName -DefaultProfile $Context -ApiVersion '2017-05-01-preview' -ExpandProperties;
        $Resource | Add-Member -MemberType NoteProperty -Name resources -Value $resources -PassThru;
    }
}

function VisitFrontDoorWAFPolicy {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject]$Resource,

        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.Core.IAzureContextContainer]$Context
    )
    process {
        # Patch Front Door WAF policy properties not fully returned from the default API version
        $Resource = Get-AzResource -Name $resource.Name -ResourceGroupName $resource.ResourceGroupName -DefaultProfile $Context -ResourceType 'Microsoft.Network/FrontDoorWebApplicationFirewallPolicies' -ExpandProperties -ApiVersion '2019-10-01';
        $Resource;
    }
}

function VisitNetworkConnection {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject]$Resource,

        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.Core.IAzureContextContainer]$Context
    )
    process {
        # Patch connections
        if (@($Resource.Properties.PSObject.Properties.Match('sharedKey')).Length -gt 0) {
            $Resource.Properties.sharedKey = "*** MASKED ***";
        }
        $Resource;
    }
}

function VisitSubscription {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject]$Resource,

        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.Core.IAzureContextContainer]$Context
    )
    process {
        $resources = @();
        $resources += Get-AzRoleAssignment -DefaultProfile $Context -IncludeClassicAdministrators | SetResourceType 'Microsoft.Authorization/roleAssignments';
        $resources += Get-AzResource -DefaultProfile $Context -ApiVersion '2017-08-01-preview' -ResourceId "/subscriptions/$($Resource.Id)/providers/Microsoft.Security/autoProvisioningSettings";
        $resources += Get-AzResource -DefaultProfile $Context -ApiVersion '2017-08-01-preview' -ResourceId "/subscriptions/$($Resource.Id)/providers/Microsoft.Security/securityContacts";
        $resources += Get-AzResource -DefaultProfile $Context -ApiVersion '2018-06-01' -ResourceId "/subscriptions/$($Resource.Id)/providers/Microsoft.Security/pricings";
        $resources += Get-AzResource -DefaultProfile $Context -ApiVersion '2019-06-01' -ResourceId "/subscriptions/$($Resource.Id)/providers/Microsoft.Authorization/policyAssignments";
        $resources += Get-AzResource -DefaultProfile $Context -ResourceType 'microsoft.insights/activityLogAlerts' -ExpandProperties;
        $Resource | Add-Member -MemberType NoteProperty -Name resources -Value $resources -PassThru;

        Get-AzPolicyDefinition -Custom -DefaultProfile $Context;
        Get-AzPolicySetDefinition -Custom -DefaultProfile $Context;
    }
}

function VisitResourceGroup {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject]$Resource,

        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.Core.IAzureContextContainer]$Context
    )
    process {
        $resources = @();
        $resources += Get-AzRoleAssignment -DefaultProfile $Context -Scope $Resource.ResourceId `
        | Where-Object { $_.Scope.StartsWith($Resource.ResourceId) } `
        | SetResourceType 'Microsoft.Authorization/roleAssignments';
        $resources += Get-AzResourceLock -DefaultProfile $Context -ResourceGroupName $Resource.ResourceGroupName | SetResourceType 'Microsoft.Authorization/locks';
        $Resource `
        | Add-Member -MemberType NoteProperty -Name Name -Value $Resource.ResourceGroupName -PassThru `
        | Add-Member -MemberType NoteProperty -Name resources -Value $resources -PassThru;
    }
}

function VisitDataExplorerCluster {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject]$Resource,

        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.Core.IAzureContextContainer]$Context
    )
    process {
        $resources = @();
        $getParams = @{
            ResourceGroupName = $Resource.ResourceGroupName
            DefaultProfile    = $Context
            ErrorAction       = 'SilentlyContinue'
        }
        $resources += Get-AzResource @getParams -Name $Resource.Name -ResourceType 'Microsoft.Kusto/clusters/databases' -ApiVersion '2021-08-27' -ExpandProperties;
        $Resource | Add-Member -MemberType NoteProperty -Name resources -Value $resources -PassThru;
    }
}

function VisitEventHubNamespaces {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject]$Resource,

        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.Core.IAzureContextContainer]$Context
    )
    process {
        $resources = @();
        $getParams = @{
            ResourceGroupName = $Resource.ResourceGroupName
            DefaultProfile    = $Context
            ErrorAction       = 'SilentlyContinue'
        }
        $resources += Get-AzResource @getParams -Name $Resource.Name -ResourceType 'Microsoft.EventHub/namespaces/eventhubs' -ApiVersion '2021-11-01' -ExpandProperties;
        $Resource | Add-Member -MemberType NoteProperty -Name resources -Value $resources -PassThru;
    }
}

function VisitServiceBusNamespaces {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject]$Resource,

        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.Core.IAzureContextContainer]$Context
    )
    process {
        $resources = @();
        $getParams = @{
            ResourceGroupName = $Resource.ResourceGroupName
            DefaultProfile    = $Context
            ErrorAction       = 'SilentlyContinue'
        }
        $resources += Get-AzResource @getParams -Name $Resource.Name -ResourceType 'Microsoft.ServiceBus/namespaces/queues' -ApiVersion '2021-06-01-preview' -ExpandProperties;
        $resources += Get-AzResource @getParams -Name $Resource.Name -ResourceType 'Microsoft.ServiceBus/namespaces/topics' -ApiVersion '2021-06-01-preview' -ExpandProperties;
        $Resource | Add-Member -MemberType NoteProperty -Name resources -Value $resources -PassThru;
    }
}

function ExpandPolicyAssignment {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject]$Assignment,

        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.Core.IAzureContextContainer]$Context
    )
    process {
        $policyDefinitionId = $Assignment.Properties.PolicyDefinitionId;

        Write-Verbose -Message "[Export] -- Expanding: $policyDefinitionId";

        $policyDefinitions = [System.Collections.Generic.List[PSObject]]@();

        if ($policyDefinitionId -like '*/providers/Microsoft.Authorization/policyDefinitions/*') {
            $definition = Get-AzPolicyDefinition -Id $policyDefinitionId -DefaultProfile $Context;
            $policyDefinitions.Add($definition);
        }
        elseif ($policyDefinitionId -like '*/providers/Microsoft.Authorization/policySetDefinitions/*') {
            $policySetDefinition = Get-AzPolicySetDefinition -Id $policyDefinitionId -DefaultProfile $Context;

            foreach ($definition in $policySetDefinition.Properties.PolicyDefinitions) {
                $definitionId = $definition.policyDefinitionId;
                Write-Verbose -Message "[Export] -- Expanding: $definitionId";
                $definition = Get-AzPolicyDefinition -Id $definitionId -DefaultProfile $Context;
                $policyDefinitions.Add($definition);
            }
        }

        $Assignment | Add-Member -MemberType NoteProperty -Name PolicyDefinitions -Value $policyDefinitions -PassThru;
    }
}

# Add additional information to resources with child resources
function ExpandResource {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject]$Resource,

        [Parameter(Mandatory = $True)]
        [Microsoft.Azure.Commands.Common.Authentication.Abstractions.Core.IAzureContextContainer]$Context
    )
    process {
        $resourceId = '';
        if ($Resource.ResourceType -eq 'Microsoft.Subscription') {
            $resourceId = $Resource.Id;
        }
        else {
            $resourceId = $Resource.ResourceId;
        }
        Write-Verbose -Message "[Export] -- Expanding: $($resourceId)";
        switch ($Resource.ResourceType) {
            'Microsoft.ApiManagement/service' { VisitAPIManagement @PSBoundParameters; }
            'Microsoft.Automation/automationAccounts' { VisitAutomationAccount @PSBoundParameters; }
            'Microsoft.Cdn/profiles/endpoints' { VisitCDNEndpoint @PSBoundParameters; }
            'Microsoft.ContainerRegistry/registries' { VisitContainerRegistry @PSBoundParameters; }
            'Microsoft.ContainerService/managedClusters' { VisitAKSCluster @PSBoundParameters; }
            'Microsoft.Sql/servers' { VisitSqlServer @PSBoundParameters; }
            'Microsoft.Sql/servers/databases' { VisitSqlDatabase @PSBoundParameters; }
            'Microsoft.DBforPostgreSQL/servers' { VisitPostgreSqlServer @PSBoundParameters; }
            'Microsoft.DBforMySQL/servers' { VisitMySqlServer @PSBoundParameters; }
            # 'Microsoft.Sql/managedInstances' { VisitSqlManagedInstance @PSBoundParameters; }
            # 'Microsoft.DataFactory/factories' { VisitDataFactoryV2 @PSBoundParameters; }
            'Microsoft.Storage/storageAccounts' { VisitStorageAccount @PSBoundParameters; }
            # "Microsoft.StorageSync/storageSyncServices" { VisitStorageSyncService @PSBoundParameters; }
            'Microsoft.Web/sites' { VisitWebApp @PSBoundParameters; }
            'Microsoft.Web/sites/slots' { VisitWebApp @PSBoundParameters; }
            'Microsoft.RecoveryServices/vaults' { VisitRecoveryServices @PSBoundParameters; }
            'Microsoft.Compute/virtualMachines' { VisitVirtualMachine @PSBoundParameters; }
            'Microsoft.KeyVault/vaults' { VisitKeyVault @PSBoundParameters; }
            'Microsoft.Network/frontDoors' { VisitFrontDoor @PSBoundParameters; }
            'Microsoft.Network/FrontDoorWebApplicationFirewallPolicies' { VisitFrontDoorWAFPolicy @PSBoundParameters; }
            'Microsoft.Network/connections' { VisitNetworkConnection @PSBoundParameters; }
            'Microsoft.Subscription' { VisitSubscription @PSBoundParameters; }
            'Microsoft.Resources/resourceGroups' { VisitResourceGroup @PSBoundParameters; }
            'Microsoft.Network/publicIPAddresses' { VisitPublicIP @PSBoundParameters; }
            'Microsoft.Cache/Redis' { VisitRedisCache @PSBoundParameters; }
            'Microsoft.Cache/redisEnterprise' { VisitRedisEnterpriseCache @PSBoundParameters; }
            'Microsoft.Kusto/Clusters' { VisitDataExplorerCluster @PSBoundParameters; }
            'Microsoft.EventHub/namespaces' { VisitEventHubNamespaces @PSBoundParameters; }
            'Microsoft.ServiceBus/namespaces' { VisitServiceBusNamespaces @PSBoundParameters; }
            default { $Resource; }
        }
    }
}

function SetResourceType {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject]$Resource,

        [Parameter(Mandatory = $True, Position = 0)]
        [String]$ResourceType
    )
    process {
        if ($ResourceType -eq 'Microsoft.Resources/resourceGroups') {
            $Resource = $Resource | Add-Member -MemberType NoteProperty -Name Id -Value $Resource.ResourceId -PassThru -Force;
        }
        $Resource | Add-Member -MemberType NoteProperty -Name ResourceType -Value $ResourceType -PassThru -Force;
    }
}

#
# Export module
#

New-Alias -Name 'Export-AzTemplateRuleData' -Value 'Export-AzRuleTemplateData' -Force;

Export-ModuleMember -Function @(
    'Export-AzRuleData'
    'Export-AzRuleTemplateData'
    'Get-AzRuleTemplateLink'
    'Export-AzPolicyAssignmentData'
    'Export-AzPolicyAssignmentRuleData'
    'Get-AzPolicyAssignmentDataSource'
);

Export-ModuleMember -Alias @(
    'Export-AzTemplateRuleData'
);

# SIG # Begin signature block
# MIInqgYJKoZIhvcNAQcCoIInmzCCJ5cCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD9v/ZgtxPRfmMK
# OrIBn/BbNBW2h9lhgLf2IGVFQYloyaCCDYEwggX/MIID56ADAgECAhMzAAACzI61
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIZfzCCGXsCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAsyOtZamvdHJTgAAAAACzDAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg+dsqiUXh
# LOdRJG63uvNptGfJkT1ywzqyRVtUzUuhc1kwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQBcZazAe39EdPHJJF2NF8gJ4f8FG929/hVzCN8nq4/e
# RzN8hXJQfAbnSkGC4inx1aCX3M6aBu9ev4ZJnz367voy/eq1Yr7GvZZMNj9LIBHL
# whFp54T4ZAfB8ELLqzw/56soZuPCZHfla8yoVMtWOQ1XcaY3VDrphlYQHhFUUolW
# 12+EMqSV9Dx6G3sZ3wkszn5ZCFdsYGGCVGarQ+e/fHu8OWAFHKeMOkdzfPtPJHDS
# XZ6zQCMvCDMOfvErtecBscToO7oeQkw+032mGTZIbFqCv7oEBjpwYk5vxPXT7FYz
# R4JZwFdBECe1QHZUd2R2p9uT3oZEE+z7EFikB8dxNz2PoYIXCTCCFwUGCisGAQQB
# gjcDAwExghb1MIIW8QYJKoZIhvcNAQcCoIIW4jCCFt4CAQMxDzANBglghkgBZQME
# AgEFADCCAVUGCyqGSIb3DQEJEAEEoIIBRASCAUAwggE8AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEII3dmGKZQkPb+QvpcbG7IBrrvaOCrAUU6gil+4Q4
# 5xciAgZjYrveewMYEzIwMjIxMTA5MTgwNzQ4Ljg3NlowBIACAfSggdSkgdEwgc4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1p
# Y3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMg
# VFNTIEVTTjpDNEJELUUzN0YtNUZGQzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgU2VydmljZaCCEVwwggcQMIIE+KADAgECAhMzAAABo/uas457hkNPAAEA
# AAGjMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# MB4XDTIyMDMwMjE4NTExNloXDTIzMDUxMTE4NTExNlowgc4xCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVy
# YXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpDNEJE
# LUUzN0YtNUZGQzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vydmlj
# ZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAO+9TcrLeyoKcCqLbNtz
# 7Nt2JbP1TEzzMhi84gS6YLI7CF6dVSA5I1bFCHcw6ZF2eF8Qiaf0o2XSXf/jp5sg
# mUYtMbGi4neAtWSNK5yht4iyQhBxn0TIQqF+NisiBxW+ehMYWEbFI+7cSdX/dWw+
# /Y8/Mu9uq3XCK5P2G+ZibVwOVH95+IiTGnmocxWgds0qlBpa1rYg3bl8XVe5L2qT
# UmJBvnQpx2bUru70lt2/HoU5bBbLKAhCPpxy4nmsrdOR3Gv4UbfAmtpQntP758NR
# Phg1bACH06FlvbIyP8/uRs3x2323daaGpJQYQoZpABg62rFDTJ4+e06tt+xbfvp8
# M9lo8a1agfxZQ1pIT1VnJdaO98gWMiMW65deFUiUR+WngQVfv2gLsv6o7+Ocpzy6
# RHZIm6WEGZ9LBt571NfCsx5z0Ilvr6SzN0QbaWJTLIWbXwbUVKYebrXEVFMyhuVG
# QHesZB+VwV386hYonMxs0jvM8GpOcx0xLyym42XA99VSpsuivTJg4o8a1ACJbTBV
# FoEA3VrFSYzOdQ6vzXxrxw6i/T138m+XF+yKtAEnhp+UeAMhlw7jP99EAlgGUl0K
# kcBjTYTz+jEyPgKadrU1of5oFi/q9YDlrVv9H4JsVe8GHMOkPTNoB4028j88OEe4
# 26BsfcXLki0phPp7irW0AbRdAgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQUUFH7szwm
# CLHPTS9Bo2irLnJji6owHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIw
# XwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9w
# cy9jcmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3Js
# MGwGCCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENB
# JTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcD
# CDANBgkqhkiG9w0BAQsFAAOCAgEAWvLep2mXw6iuBxGu0PsstmXI5gLmgPkTKQnj
# gZlsoeipsta9oku0MTVxlHVdcdBbFcVHMLRRkUFIkfKnaclyl5eyj03weD6b/pUf
# FyDZB8AZpGUXhTYLNR8PepM6yD6g+0E1nH0MhOGoE6XFufkbn6eIdNTGuWwBeEr2
# DNiGhDGlwaUH5ELz3htuyMyWKAgYF28C4iyyhYdvlG9VN6JnC4mc/EIt50BCHp8Z
# QAk7HC3ROltg1gu5NjGaSVdisai5OJWf6e5sYQdDBNYKXJdiHei1N7K+L5s1vV+C
# 6d3TsF9+ANpioBDAOGnFSYt4P+utW11i37iLLLb926pCL4Ly++GU0wlzYfn7n22R
# yQmvD11oyiZHhmRssDBqsA+nvCVtfnH183Df5oBBVskzZcJTUjCxaagDK7AqB6QA
# 3H7l/2SFeeqfX/Dtdle4B+vPV4lq1CCs0A1LB9lmzS0vxoRDusY80DQi10K3SfZK
# 1hyyaj9a8pbZG0BsBp2Nwc4xtODEeBTWoAzF9ko4V6d09uFFpJrLoV+e8cJU/hT3
# +SlW7dnr5dtYvziHTpZuuRv4KU6F3OQzNpHf7cBLpWKRXRjGYdVnAGb8NzW6wWTj
# ZjMCNdCFG7pkKLMOGdqPDFdfk+EYE5RSG9yxS76cPfXqRKVtJZScIF64ejnXbFIs
# 5bh8KwEwggdxMIIFWaADAgECAhMzAAAAFcXna54Cm0mZAAAAAAAVMA0GCSqGSIb3
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
# vzhwRNGQ8cirOoo6CGJ/2XBjU02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYICzzCC
# AjgCAQEwgfyhgdSkgdEwgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNv
# MSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpDNEJELUUzN0YtNUZGQzElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUA
# Hl/pXkLMAbPapCwa+GXc3SlDDROggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFt
# cCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOcVy98wIhgPMjAyMjExMDkxMDQ5
# MDNaGA8yMDIyMTExMDEwNDkwM1owdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA5xXL
# 3wIBADAHAgEAAgIZ2DAHAgEAAgIRYjAKAgUA5xcdXwIBADA2BgorBgEEAYRZCgQC
# MSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqG
# SIb3DQEBBQUAA4GBAGRajpAYlGoQYEFdqf8D1RJAFBFEH/YAAIHTOei94w55bkto
# CXpwyDWTF5JA24fqdQfcV7EfX6PHj4iIozvCEYrhrJ3C6RU2zFJeb/cGJK+E7dUG
# BpCFOBkudgiB6pBn53LyKYJdx9OC0ycy3FaieLUw/2Xap02f/OdZdTS57QH9MYIE
# DTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGj
# +5qzjnuGQ08AAQAAAaMwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzEN
# BgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQglMoad0G/4mzwjNbyQWtb1HYH
# 1sxcBgMmWjsICNMGz0AwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCCM+Liw
# BnHMMoOd/sgbaYxpwvEJlREZl/pTPklz6euN/jCBmDCBgKR+MHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABo/uas457hkNPAAEAAAGjMCIEIHXHsYFZ
# ZldCs4cQYsMK2olIL+2T/jEWWWDZu1iGuh3bMA0GCSqGSIb3DQEBCwUABIICAIPj
# p0S+bQrFfsqWErfWUifyEtX0kI4zPrCU7KBrJ454Qv1Hsy70LvmtrQ275xAdGBBE
# RLRBOY7q/TpBrYm3ozb8RV6JgZK0yjFpoTK9JGkGiex2WkQcNea6Veau3wb8xMHX
# XwgqGTBwJ7nzfba1C7/Cs9w9PkDUvpWX4cWPVQtw0XJxoVGDSt8RQcHeMKDUj99e
# aEmboajXsKHdm2wEukm6uM1URQvL06NliJCO+9GU5Q1J7PNbUeyaTpkNgk7ar0Ha
# fSijOFYdLfo6z42hlCHYYhAPklk7DhDmWjYHbYHDnz9pawjxHr+0A+oqktJO7rJB
# +PyFQ18iQxz6ZQwsjTwBrC9EdoKJyUpSts7NM2L1z3LnW+htg5omTn7b9dJcIDA7
# TtP0QgimbyfqhjefexJMEvTsNHivX6UeAsGbD8QpEuQJ6truH/2TvnOR318b87U0
# LG2OeNknHdg+5HVrhbdoEpgXlP4ztFd3DnoR5lVRJu1ZQ10XY2fsB205k+9dEFqO
# SE+sBYOfmvTeVgwh31YoPDF4iuXUO+Ry5VfStIHBQIWG3sqPo6X3VxBqutX44Rt1
# XFb7+0ilsdUtwWNMzsSif3qD34WzGf7A0EojWpXcz7uoE8bR0BUVRea1d/4T1xEo
# nez8khX/RvbC0oOy5Mf6FrYKXc+RDT5lBMBoZawM
# SIG # End signature block
