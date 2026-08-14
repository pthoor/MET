function Resolve-METEffectivePolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]] $Subjects,
        [Parameter(Mandatory)] [hashtable] $GroupCache,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Rules,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Policies,
        [Parameter(Mandatory)] [string] $PolicyLinkProperty,
        [Parameter(Mandatory)] [string] $ProtectionType,
        [AllowEmptyCollection()] [object[]] $PresetRules = @(),
        [switch] $IncludePresets,
        [ValidateSet('Recipient','Sender')] [string] $ScopeType = 'Recipient',
        [System.Collections.Generic.List[string]] $RetrievalErrors
    )

    function Get-ScopeDescription {
        param([object] $Rule)
        if (-not $Rule) { return 'Default catch-all' }
        $direct = if ($ScopeType -eq 'Sender') { 'From' } else { 'SentTo' }
        $group = if ($ScopeType -eq 'Sender') { 'FromMemberOf' } else { 'SentToMemberOf' }
        $domain = if ($ScopeType -eq 'Sender') { 'SenderDomainIs' } else { 'RecipientDomainIs' }
        $exceptDirect = if ($ScopeType -eq 'Sender') { 'ExceptIfFrom' } else { 'ExceptIfSentTo' }
        $exceptGroup = if ($ScopeType -eq 'Sender') { 'ExceptIfFromMemberOf' } else { 'ExceptIfSentToMemberOf' }
        $exceptDomain = if ($ScopeType -eq 'Sender') { 'ExceptIfSenderDomainIs' } else { 'ExceptIfRecipientDomainIs' }
        $parts = [System.Collections.Generic.List[string]]::new()
        if ($Rule.$direct) { $parts.Add("$(if ($ScopeType -eq 'Sender') { 'Senders' } else { 'Recipients' }): $(@($Rule.$direct).Count)") }
        if ($Rule.$group) { $parts.Add("Groups: $(@($Rule.$group).Count)") }
        if ($Rule.$domain) { $parts.Add("Domains: $(@($Rule.$domain) -join ', ')") }
        if ($parts.Count -eq 0) { $parts.Add('Catch-all (no inclusion conditions)') }
        $exceptions = @($Rule.$exceptDirect | Where-Object { $_ }).Count + @($Rule.$exceptGroup | Where-Object { $_ }).Count + @($Rule.$exceptDomain | Where-Object { $_ }).Count
        if ($exceptions -gt 0) { $parts.Add("Exceptions: $exceptions") }
        $parts -join '; '
    }

    $assignments = @{}
    $summaries = [System.Collections.Generic.List[object]]::new()

    if ($IncludePresets) {
        foreach ($tier in @('Strict','Standard')) {
            $stableName = "$tier Preset Security Policy"
            $rule = $PresetRules | Where-Object { $_.Name -eq $stableName -and $_.State -eq 'Enabled' } | Select-Object -First 1
            $policy = $Policies | Where-Object { $_.Name -eq $stableName -or $_.Name -like "$stableName*" } | Select-Object -First 1
            $covered = if ($rule) { @(Expand-METRuleRecipients -Rule $rule -AllMailboxes $Subjects -GroupCache $GroupCache -ScopeType $ScopeType -RetrievalErrors $RetrievalErrors) } else { @() }
            foreach ($subject in $covered) {
                if (-not $assignments.ContainsKey($subject)) {
                    $assignments[$subject] = [PSCustomObject]@{ Recipient=$subject; PolicyName=if ($policy) {$policy.Name} else {$stableName}; PolicyType='Preset'; Tier=$tier; Priority=$null; ScopeDescription=Get-ScopeDescription $rule; Policy=$policy; Rule=$rule }
                }
            }
            if ($rule -or $policy) {
                $summaries.Add([PSCustomObject]@{ PolicyName=if ($policy) {$policy.Name} else {$stableName}; PolicyType='Preset'; Tier=$tier; Priority=$null; ScopeDescription=Get-ScopeDescription $rule; EffectiveRecipients=@($covered | Where-Object { $assignments[$_].Tier -eq $tier }).Count; State=if ($rule) {'Enabled'} else {'Inactive'}; Policy=$policy; Rule=$rule })
            }
            if ($rule -and -not $policy -and $null -ne $RetrievalErrors) { $RetrievalErrors.Add("Enabled $tier preset rule was returned, but its $ProtectionType policy object was not returned.") }
        }
    }

    foreach ($rule in @($Rules | Where-Object State -eq 'Enabled' | Sort-Object Priority)) {
        $policyName = [string]$rule.$PolicyLinkProperty
        if (-not $policyName) { $policyName = [string]$rule.Name }
        $policy = $Policies | Where-Object Name -eq $policyName | Select-Object -First 1
        if (-not $policy -and $null -ne $RetrievalErrors) { $RetrievalErrors.Add("Enabled $ProtectionType rule '$($rule.Name)' references policy '$policyName', but that policy was not returned.") }
        $matched = @(Expand-METRuleRecipients -Rule $rule -AllMailboxes $Subjects -GroupCache $GroupCache -ScopeType $ScopeType -RetrievalErrors $RetrievalErrors)
        $covered = @($matched | Where-Object { -not $assignments.ContainsKey($_) })
        $shadowed = @($matched | Where-Object { $assignments.ContainsKey($_) })
        $shadowedBy = @($shadowed | ForEach-Object {
            $prior = $assignments[$_]
            if ($prior.PolicyType -eq 'Preset') { "Preset: '$($prior.PolicyName)'" }
            else {
                $direct = if ($ScopeType -eq 'Sender') { 'From' } else { 'SentTo' }
                $group = if ($ScopeType -eq 'Sender') { 'FromMemberOf' } else { 'SentToMemberOf' }
                $domain = if ($ScopeType -eq 'Sender') { 'SenderDomainIs' } else { 'RecipientDomainIs' }
                if (-not $prior.Rule.$direct -and -not $prior.Rule.$group -and -not $prior.Rule.$domain) { "CustomCatchAll: '$($prior.PolicyName)'" } else { "Custom: '$($prior.PolicyName)'" }
            }
        } | Sort-Object -Unique)
        foreach ($subject in $covered) { $assignments[$subject] = [PSCustomObject]@{ Recipient=$subject; PolicyName=$policyName; PolicyType='Custom'; Tier='Custom'; Priority=$rule.Priority; ScopeDescription=Get-ScopeDescription $rule; Policy=$policy; Rule=$rule } }
        $summaries.Add([PSCustomObject]@{ PolicyName=$policyName; PolicyType='Custom'; Tier='Custom'; Priority=$rule.Priority; ScopeDescription=Get-ScopeDescription $rule; MatchedRecipients=$matched.Count; EffectiveRecipients=$covered.Count; ShadowedRecipients=$shadowed.Count; ShadowedBy=$shadowedBy; State='Enabled'; Policy=$policy; Rule=$rule })
    }

    foreach ($rule in @($Rules | Where-Object State -ne 'Enabled')) {
        $policyName = if ($rule.$PolicyLinkProperty) { [string]$rule.$PolicyLinkProperty } else { [string]$rule.Name }
        $policy = $Policies | Where-Object Name -eq $policyName | Select-Object -First 1
        $summaries.Add([PSCustomObject]@{ PolicyName=$policyName; PolicyType='Custom'; Tier='Custom'; Priority=$rule.Priority; ScopeDescription=Get-ScopeDescription $rule; EffectiveRecipients=0; State=if ($rule.State) {[string]$rule.State} else {'Disabled'}; Policy=$policy; Rule=$rule })
    }

    $defaultPolicy = $Policies | Where-Object IsDefault -eq $true | Select-Object -First 1
    $defaultName = if ($defaultPolicy) { [string]$defaultPolicy.Name } else { "Default $ProtectionType policy" }
    $defaultCount = 0
    foreach ($subject in $Subjects) {
        if (-not $assignments.ContainsKey($subject)) {
            $assignments[$subject] = [PSCustomObject]@{ Recipient=$subject; PolicyName=$defaultName; PolicyType='Default'; Tier='Default'; Priority=$null; ScopeDescription='Default catch-all'; Policy=$defaultPolicy; Rule=$null }
            $defaultCount++
        }
    }
    if ($defaultPolicy -or $defaultCount -gt 0) { $summaries.Add([PSCustomObject]@{ PolicyName=$defaultName; PolicyType='Default'; Tier='Default'; Priority=$null; ScopeDescription='Default catch-all'; EffectiveRecipients=$defaultCount; State='Enabled'; Policy=$defaultPolicy; Rule=$null }) }
    if ($defaultCount -gt 0 -and -not $defaultPolicy -and $null -ne $RetrievalErrors) { $RetrievalErrors.Add("Subjects fall through to the default $ProtectionType policy, but that policy object was not returned.") }

    $associated = @($Rules | ForEach-Object { if ($_.$PolicyLinkProperty) { [string]$_.$PolicyLinkProperty } else { [string]$_.Name } })
    foreach ($policy in @($Policies | Where-Object { $_.IsDefault -ne $true -and $associated -notcontains $_.Name -and $_.Name -notmatch '^(Strict|Standard) Preset Security Policy' })) {
        $summaries.Add([PSCustomObject]@{ PolicyName=[string]$policy.Name; PolicyType='Unassociated'; Tier='Custom'; Priority=$null; ScopeDescription='No associated rule'; EffectiveRecipients=0; State='Inactive'; Policy=$policy; Rule=$null })
    }

    [PSCustomObject]@{ RecipientAssignments=@($Subjects | ForEach-Object { $assignments[$_] }); PolicySummaries=@($summaries) }
}
