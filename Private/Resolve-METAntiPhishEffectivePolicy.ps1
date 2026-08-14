function Resolve-METAntiPhishEffectivePolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]] $AllMailboxes,
        [Parameter(Mandatory)] [hashtable] $GroupCache,
        [AllowEmptyCollection()] [object[]] $Rules,
        [AllowEmptyCollection()] [object[]] $Policies,
        [AllowEmptyCollection()] [object[]] $PresetRules,
        [System.Collections.Generic.List[string]] $RetrievalErrors
    )

    function Get-AntiPhishScopeDescription {
        param([object] $Rule)
        if (-not $Rule) { return 'Default catch-all' }
        $parts = [System.Collections.Generic.List[string]]::new()
        if ($Rule.SentTo) { $parts.Add("Recipients: $(@($Rule.SentTo).Count)") }
        if ($Rule.SentToMemberOf) { $parts.Add("Groups: $(@($Rule.SentToMemberOf).Count)") }
        if ($Rule.RecipientDomainIs) { $parts.Add("Domains: $(@($Rule.RecipientDomainIs) -join ', ')") }
        if ($parts.Count -eq 0) { $parts.Add('Catch-all (no inclusion conditions)') }
        $exceptions = @($Rule.ExceptIfSentTo | Where-Object { $_ }).Count + @($Rule.ExceptIfSentToMemberOf | Where-Object { $_ }).Count +
            @($Rule.ExceptIfRecipientDomainIs | Where-Object { $_ }).Count
        if ($exceptions -gt 0) { $parts.Add("Exceptions: $exceptions") }
        return ($parts -join '; ')
    }

    if (-not $PSBoundParameters.ContainsKey('Rules')) {
        try { $Rules = @(Get-AntiPhishRule -ErrorAction Stop) }
        catch {
            $Rules = @()
            if ($null -ne $RetrievalErrors) { $RetrievalErrors.Add("Unable to retrieve anti-phishing rules. $($_.ToString())") }
        }
    }
    if (-not $PSBoundParameters.ContainsKey('Policies')) {
        try { $Policies = @(Get-AntiPhishPolicy -ErrorAction Stop) }
        catch {
            $Policies = @()
            if ($null -ne $RetrievalErrors) { $RetrievalErrors.Add("Unable to retrieve anti-phishing policies. $($_.ToString())") }
        }
    }
    if (-not $PSBoundParameters.ContainsKey('PresetRules')) {
        try { $PresetRules = @(Get-ATPProtectionPolicyRule -ErrorAction Stop) }
        catch {
            $PresetRules = @()
            if ($null -ne $RetrievalErrors) { $RetrievalErrors.Add("Unable to retrieve MDO preset policy rules. $($_.ToString())") }
        }
    }

    $assignments = @{}
    $policyDetails = [System.Collections.Generic.List[object]]::new()
    $evaluationRules = @($PresetRules | Where-Object { $_.State -eq 'Enabled' -and $_.Name -match 'Evaluation' })
    if ($evaluationRules.Count -gt 0 -and $null -ne $RetrievalErrors) {
        $RetrievalErrors.Add('An enabled Defender for Office 365 evaluation policy was detected. Its anti-phishing precedence is not yet modeled.')
    }

    foreach ($tier in @('Strict', 'Standard')) {
        $stableName = "$tier Preset Security Policy"
        $rule = $PresetRules | Where-Object { $_.Name -eq $stableName -and $_.State -eq 'Enabled' } | Select-Object -First 1
        $policy = $Policies | Where-Object { $_.Name -eq $stableName } | Select-Object -First 1
        if (-not $policy) { $policy = $Policies | Where-Object { $_.Name -like "$stableName*" } | Select-Object -First 1 }
        $covered = if ($rule) {
            @(Expand-METRuleRecipients -Rule $rule -AllMailboxes $AllMailboxes -GroupCache $GroupCache -RetrievalErrors $RetrievalErrors)
        } else { @() }
        foreach ($recipient in $covered) {
            if (-not $assignments.ContainsKey($recipient)) {
                $assignments[$recipient] = [PSCustomObject]@{
                    Recipient = $recipient; PolicyName = if ($policy) { $policy.Name } else { $stableName }
                    PolicyType = 'Preset'; Tier = $tier; Priority = $null
                    ScopeDescription = Get-AntiPhishScopeDescription $rule; Policy = $policy; Rule = $rule
                }
            }
        }
        if ($rule -or $policy) {
            $policyDetails.Add([PSCustomObject]@{
                PolicyName = if ($policy) { $policy.Name } else { $stableName }
                PolicyType = 'Preset'; Tier = $tier; Priority = $null
                ScopeDescription = Get-AntiPhishScopeDescription $rule
                EffectiveRecipients = @($covered | Where-Object { $assignments[$_].Tier -eq $tier }).Count
                State = if ($rule) { 'Enabled' } else { 'Inactive' }; Policy = $policy; Rule = $rule
            })
        }
        if ($rule -and -not $policy -and $null -ne $RetrievalErrors) {
            $RetrievalErrors.Add("Enabled $tier preset rule was returned, but its anti-phishing policy object was not returned.")
        }
    }

    $presetPolicyNames = @($policyDetails | Where-Object PolicyType -eq 'Preset' | ForEach-Object PolicyName)
    $customRules = @($Rules | Where-Object {
        $_.State -eq 'Enabled' -and $_.Name -notmatch '^(Strict|Standard) Preset Security Policy'
    } | Sort-Object Priority)
    foreach ($rule in $customRules) {
        $policyName = if ($rule.AntiPhishPolicy) { [string]$rule.AntiPhishPolicy } else { [string]$rule.Name }
        $policy = $Policies | Where-Object { $_.Name -eq $policyName } | Select-Object -First 1
        if (-not $policy -and $null -ne $RetrievalErrors) {
            $RetrievalErrors.Add("Enabled anti-phishing rule '$($rule.Name)' references policy '$policyName', but that policy was not returned.")
        }
        $matched = @(Expand-METRuleRecipients -Rule $rule -AllMailboxes $AllMailboxes -GroupCache $GroupCache -RetrievalErrors $RetrievalErrors)
        $covered = @($matched | Where-Object { -not $assignments.ContainsKey($_) })
        $shadowed = @($matched | Where-Object { $assignments.ContainsKey($_) })
        $shadowedBy = @($shadowed | ForEach-Object {
            $prior = $assignments[$_]
            if ($prior.PolicyType -eq 'Preset') { "Preset: '$($prior.PolicyName)'" }
            elseif (-not $prior.Rule.SentTo -and -not $prior.Rule.SentToMemberOf -and -not $prior.Rule.RecipientDomainIs) { "CustomCatchAll: '$($prior.PolicyName)'" }
            else { "Custom: '$($prior.PolicyName)'" }
        } | Sort-Object -Unique)
        foreach ($recipient in $covered) {
            $assignments[$recipient] = [PSCustomObject]@{
                Recipient = $recipient; PolicyName = $policyName; PolicyType = 'Custom'; Tier = 'Custom'
                Priority = $rule.Priority; ScopeDescription = Get-AntiPhishScopeDescription $rule
                Policy = $policy; Rule = $rule
            }
        }
        $policyDetails.Add([PSCustomObject]@{
            PolicyName = $policyName; PolicyType = 'Custom'; Tier = 'Custom'; Priority = $rule.Priority
            ScopeDescription = Get-AntiPhishScopeDescription $rule; MatchedRecipients = @($matched).Count
            EffectiveRecipients = @($covered).Count; ShadowedRecipients = @($shadowed).Count; ShadowedBy = $shadowedBy
            State = 'Enabled'; Policy = $policy; Rule = $rule
        })
    }

    foreach ($rule in @($Rules | Where-Object { $_.State -ne 'Enabled' })) {
        $policyName = if ($rule.AntiPhishPolicy) { [string]$rule.AntiPhishPolicy } else { [string]$rule.Name }
        $policy = $Policies | Where-Object Name -eq $policyName | Select-Object -First 1
        $policyDetails.Add([PSCustomObject]@{
            PolicyName = $policyName; PolicyType = 'Custom'; Tier = 'Custom'; Priority = $rule.Priority
            ScopeDescription = Get-AntiPhishScopeDescription $rule; EffectiveRecipients = 0
            State = if ($rule.State) { [string]$rule.State } else { 'Disabled' }; Policy = $policy; Rule = $rule
        })
    }

    $defaultPolicy = $Policies | Where-Object { $_.IsDefault -eq $true -or $_.Name -eq 'Office365 AntiPhish Default' } | Select-Object -First 1
    $defaultCount = 0
    foreach ($recipient in $AllMailboxes) {
        if (-not $assignments.ContainsKey($recipient)) {
            $assignments[$recipient] = [PSCustomObject]@{
                Recipient = $recipient; PolicyName = if ($defaultPolicy) { $defaultPolicy.Name } else { 'Office365 AntiPhish Default' }
                PolicyType = 'Default'; Tier = 'Default'; Priority = $null; ScopeDescription = 'Default catch-all'
                Policy = $defaultPolicy; Rule = $null
            }
            $defaultCount++
        }
    }
    if ($defaultPolicy -or $defaultCount -gt 0) {
        $policyDetails.Add([PSCustomObject]@{
            PolicyName = if ($defaultPolicy) { $defaultPolicy.Name } else { 'Office365 AntiPhish Default' }
            PolicyType = 'Default'; Tier = 'Default'; Priority = $null; ScopeDescription = 'Default catch-all'
            EffectiveRecipients = $defaultCount; State = 'Enabled'; Policy = $defaultPolicy; Rule = $null
        })
    }
    if ($defaultCount -gt 0 -and -not $defaultPolicy -and $null -ne $RetrievalErrors) {
        $RetrievalErrors.Add('Recipients fall through to the default anti-phishing policy, but that policy object was not returned.')
    }

    $associated = @($Rules | ForEach-Object { if ($_.AntiPhishPolicy) { [string]$_.AntiPhishPolicy } else { [string]$_.Name } })
    foreach ($policy in @($Policies | Where-Object {
        $_.IsDefault -ne $true -and $_.Name -notin $presetPolicyNames -and $associated -notcontains $_.Name
    })) {
        $policyDetails.Add([PSCustomObject]@{
            PolicyName = [string]$policy.Name; PolicyType = 'Unassociated'; Tier = 'Custom'; Priority = $null
            ScopeDescription = 'No associated rule'; EffectiveRecipients = 0; State = 'Inactive'
            Policy = $policy; Rule = $null
        })
    }

    [PSCustomObject]@{
        RecipientAssignments = @($AllMailboxes | ForEach-Object { $assignments[$_] })
        PolicySummaries = @($policyDetails)
    }
}
