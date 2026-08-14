function Resolve-METSafeLinksEffectivePolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]] $AllMailboxes,
        [Parameter(Mandatory)] [hashtable] $GroupCache,
        [AllowEmptyCollection()] [object[]] $Rules,
        [AllowEmptyCollection()] [object[]] $Policies,
        [AllowEmptyCollection()] [object[]] $PresetRules,
        [System.Collections.Generic.List[string]] $RetrievalErrors
    )

    function Get-RuleScopeDescription {
        param([object] $Rule)
        if (-not $Rule) { return 'Microsoft-managed fallback' }

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
        try { $Rules = @(Get-SafeLinksRule -ErrorAction Stop) }
        catch {
            $Rules = @()
            if ($null -ne $RetrievalErrors) { $RetrievalErrors.Add("Unable to retrieve Safe Links rules. $($_.ToString())") }
        }
    }
    if (-not $PSBoundParameters.ContainsKey('Policies')) {
        try { $Policies = @(Get-SafeLinksPolicy -ErrorAction Stop) }
        catch {
            $Policies = @()
            if ($null -ne $RetrievalErrors) { $RetrievalErrors.Add("Unable to retrieve Safe Links policies. $($_.ToString())") }
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
    $enabledRules = @($Rules | Where-Object { $_.State -eq 'Enabled' } | Sort-Object Priority)

    $evaluationRules = @($PresetRules | Where-Object {
        $_.State -eq 'Enabled' -and $_.Name -match 'Evaluation'
    })
    if ($evaluationRules.Count -gt 0 -and $null -ne $RetrievalErrors) {
        $RetrievalErrors.Add('An enabled Defender for Office 365 evaluation policy was detected. Its Safe Links precedence is not yet modeled, so effective coverage cannot be established authoritatively.')
    }

    # Preset policies always take precedence over custom policies. Strict wins
    # over Standard for recipients included in both preset rules.
    foreach ($tier in @('Strict', 'Standard')) {
        $presetName = "$tier Preset Security Policy"
        $presetRule = $PresetRules | Where-Object { $_.Name -eq $presetName -and $_.State -eq 'Enabled' } |
            Select-Object -First 1
        $presetPolicy = $Policies | Where-Object { $_.Name -eq $presetName } | Select-Object -First 1
        if (-not $presetPolicy) {
            # Exchange-generated preset Safe Links policy names include a numeric
            # suffix. Bind those objects to the stable preset-rule identity.
            $presetPolicy = $Policies | Where-Object { $_.Name -like "$presetName*" } | Select-Object -First 1
        }
        $covered = if ($presetRule) {
            @(Expand-METRuleRecipients -Rule $presetRule -AllMailboxes $AllMailboxes -GroupCache $GroupCache -RetrievalErrors $RetrievalErrors)
        } else { @() }
        foreach ($recipient in $covered) {
            if (-not $assignments.ContainsKey($recipient)) {
                $assignments[$recipient] = [PSCustomObject]@{
                    Recipient = $recipient; PolicyName = if ($presetPolicy) { $presetPolicy.Name } else { $presetName }
                    PolicyType = 'Preset'; Tier = $tier; Priority = $null
                    ScopeDescription = Get-RuleScopeDescription $presetRule
                    Policy = $presetPolicy; Rule = $presetRule
                }
            }
        }
        if ($presetRule -or $presetPolicy) {
            $policyDetails.Add([PSCustomObject]@{
                PolicyName = if ($presetPolicy) { $presetPolicy.Name } else { $presetName }
                PolicyType = 'Preset'; Tier = $tier; Priority = $null
                ScopeDescription = Get-RuleScopeDescription $presetRule
                EffectiveRecipients = @($covered | Where-Object { $assignments[$_].Tier -eq $tier }).Count
                State = if ($presetRule.State) { [string]$presetRule.State } else { 'Inactive' }
                Policy = $presetPolicy; Rule = $presetRule
            })
            if ($presetRule -and -not $presetPolicy -and $null -ne $RetrievalErrors) {
                $RetrievalErrors.Add("Enabled $tier preset rule was returned, but its Safe Links policy object was not returned.")
            }
        }
    }

    foreach ($rule in $enabledRules) {
        $policyName = [string]$rule.SafeLinksPolicy
        if (-not $policyName) { $policyName = [string]$rule.Name }
        $policy = $Policies | Where-Object { $_.Name -eq $policyName } | Select-Object -First 1
        if (-not $policy -and $null -ne $RetrievalErrors) {
            $RetrievalErrors.Add("Enabled Safe Links rule '$($rule.Name)' references policy '$policyName', but that policy was not returned.")
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
            if (-not $assignments.ContainsKey($recipient)) {
                $assignments[$recipient] = [PSCustomObject]@{
                    Recipient = $recipient; PolicyName = $policyName; PolicyType = 'Custom'; Tier = 'Custom'
                    Priority = $rule.Priority; ScopeDescription = Get-RuleScopeDescription $rule
                    Policy = $policy; Rule = $rule
                }
            }
        }
        $policyDetails.Add([PSCustomObject]@{
            PolicyName = $policyName; PolicyType = 'Custom'; Tier = 'Custom'; Priority = $rule.Priority
            ScopeDescription = Get-RuleScopeDescription $rule; MatchedRecipients = @($matched).Count
            EffectiveRecipients = @($covered).Count; ShadowedRecipients = @($shadowed).Count; ShadowedBy = $shadowedBy
            State = [string]$rule.State
            Policy = $policy; Rule = $rule
        })
    }

    foreach ($rule in @($Rules | Where-Object { $_.State -ne 'Enabled' })) {
        $policyName = if ($rule.SafeLinksPolicy) { [string]$rule.SafeLinksPolicy } else { [string]$rule.Name }
        $policy = $Policies | Where-Object { $_.Name -eq $policyName } | Select-Object -First 1
        $policyDetails.Add([PSCustomObject]@{
            PolicyName = $policyName; PolicyType = 'Custom'; Tier = 'Custom'; Priority = $rule.Priority
            ScopeDescription = Get-RuleScopeDescription $rule; EffectiveRecipients = 0
            State = if ($rule.State) { [string]$rule.State } else { 'Disabled' }
            Policy = $policy; Rule = $rule
        })
    }

    $associatedPolicyNames = @($Rules | ForEach-Object {
        if ($_.SafeLinksPolicy) { [string]$_.SafeLinksPolicy } else { [string]$_.Name }
    })
    foreach ($policy in @($Policies | Where-Object {
        $_.Name -ne 'Built-In Protection Policy' -and
        $_.Name -notmatch '^(Strict|Standard) Preset Security Policy' -and
        $associatedPolicyNames -notcontains $_.Name
    })) {
        $policyDetails.Add([PSCustomObject]@{
            PolicyName = [string]$policy.Name; PolicyType = 'Unassociated'; Tier = 'Custom'; Priority = $null
            ScopeDescription = 'No associated rule'; EffectiveRecipients = 0; State = 'Inactive'
            Policy = $policy; Rule = $null
        })
    }

    $builtIn = $Policies | Where-Object { $_.Name -eq 'Built-In Protection Policy' } | Select-Object -First 1
    $builtInCount = 0
    foreach ($recipient in $AllMailboxes) {
        if (-not $assignments.ContainsKey($recipient)) {
            $assignments[$recipient] = [PSCustomObject]@{
                Recipient = $recipient; PolicyName = 'Built-In Protection Policy'; PolicyType = 'BuiltIn'
                Tier = 'BuiltIn'; Priority = $null; ScopeDescription = 'Microsoft-managed fallback'
                Policy = $builtIn; Rule = $null
            }
            $builtInCount++
        }
    }
    if ($builtIn -or $builtInCount -gt 0) {
        $policyDetails.Add([PSCustomObject]@{
            PolicyName = 'Built-In Protection Policy'; PolicyType = 'BuiltIn'; Tier = 'BuiltIn'
            Priority = $null; ScopeDescription = 'Microsoft-managed fallback'
            EffectiveRecipients = $builtInCount; State = 'Enabled'; Policy = $builtIn; Rule = $null
        })
    }
    if ($builtInCount -gt 0 -and -not $builtIn -and $null -ne $RetrievalErrors) {
        $RetrievalErrors.Add('Recipients fall through to Built-in Protection, but the Built-in Safe Links policy object was not returned.')
    }

    return [PSCustomObject]@{
        RecipientAssignments = @($AllMailboxes | ForEach-Object { $assignments[$_] })
        PolicySummaries = @($policyDetails)
    }
}
