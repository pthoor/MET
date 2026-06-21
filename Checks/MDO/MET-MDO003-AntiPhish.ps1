try {
    $antiPhishRules    = @(Get-AntiPhishRule    -ErrorAction Stop | Sort-Object Priority)
    $antiPhishPolicies = @(Get-AntiPhishPolicy  -ErrorAction Stop)
}
catch {
    New-METCheckResult -CheckId 'MET-MDO003' -Category MDO -Name 'Anti-Phishing' `
        -Result Fail -Severity High -AffectedObject 'Anti-Phish Policies' `
        -Finding 'Unable to retrieve anti-phishing policies' `
        -Recommendation 'Ensure the account has Security Reader or higher permissions.' `
        -ReferenceUrl 'https://aka.ms/mdo-antiphishing' -ErrorMessage $_.ToString()
    return
}

$ruleByPolicy = @{}
foreach ($r in $antiPhishRules) { $ruleByPolicy[$r.AntiPhishPolicy] = $r }

foreach ($policy in $antiPhishPolicies) {
    $isDefault = $policy.IsDefault -eq $true
    $rule      = $ruleByPolicy[$policy.Name]

    # Skip custom policies whose rule is absent or disabled — they have no effect.
    if (-not $isDefault -and (-not $rule -or $rule.State -ne 'Enabled')) { continue }

    $scope = if ($isDefault) {
        'catch-all (default — applies to all uncovered recipients)'
    } else {
        Get-METRuleScope -Rule $rule
    }
    $label = "$($policy.Name) [$scope]"

    $issues = [System.Collections.Generic.List[string]]::new()

    if (-not $policy.EnableMailboxIntelligence)             { $issues.Add('Mailbox intelligence is disabled') }
    if (-not $policy.EnableMailboxIntelligenceProtection)   { $issues.Add('Mailbox intelligence protection is disabled') }
    if (-not $policy.EnableFirstContactSafetyTips)          { $issues.Add('First-contact safety tip is disabled') }
    if (-not $policy.EnableSimilarUsersSafetyTips)          { $issues.Add('Similar-user safety tips are disabled') }
    if (-not $policy.EnableSimilarDomainsSafetyTips)        { $issues.Add('Similar-domain safety tips are disabled') }
    if (-not $policy.EnableUnusualCharactersSafetyTips)     { $issues.Add('Unusual-characters safety tips are disabled') }
    if (-not $policy.EnableTargetedUserProtection -or
        -not $policy.TargetedUsersToProtect)                 { $issues.Add('Targeted user impersonation protection is not configured') }

    $impersonationAction = $policy.TargetedUserProtectionAction
    if ($impersonationAction -eq 'NoAction' -or -not $impersonationAction) {
        $issues.Add('Impersonation detection action is set to NoAction')
    }

    # PhishThresholdLevel: 1=Standard (default), 2=Aggressive, 3=More aggressive, 4=Most aggressive
    # Recommended: 3 (Standard profile) or 4 (Strict profile). Flag anything at 1 as a warning.
    if ($null -ne $policy.PhishThresholdLevel -and $policy.PhishThresholdLevel -le 1) {
        $issues.Add("Phishing email threshold is $($policy.PhishThresholdLevel) (default) — recommended 3 or higher for better phishing catch rate")
    }

    if ($issues.Count -gt 0) {
        New-METCheckResult -CheckId 'MET-MDO003' -Category MDO -Name 'Anti-Phishing' `
            -Result Fail -Severity High -AffectedObject $label `
            -Finding ($issues -join '; ') `
            -Recommendation 'Enable mailbox intelligence and its protection action, all safety tips (first-contact, similar-user, similar-domain, unusual-characters), and impersonation protection with a quarantine or move-to-junk action. Raise PhishThresholdLevel to 3 or 4 for more aggressive phishing detection.' `
            -ReferenceUrl 'https://aka.ms/mdo-antiphishing'
    }
    else {
        New-METCheckResult -CheckId 'MET-MDO003' -Category MDO -Name 'Anti-Phishing' `
            -Result Pass -Severity High -AffectedObject $label `
            -Finding 'Anti-phishing policy is correctly configured' `
            -ReferenceUrl 'https://aka.ms/mdo-antiphishing'
    }
}
