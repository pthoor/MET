try {
    $spamRules    = @(Get-HostedContentFilterRule    -ErrorAction Stop | Sort-Object Priority)
    $spamPolicies = @(Get-HostedContentFilterPolicy  -ErrorAction Stop)
}
catch {
    New-METCheckResult -CheckId 'MET-MDO009' -Category MDO -Name 'Zero-Hour Auto Purge (ZAP)' `
        -Result Fail -Severity High -AffectedObject 'Hosted Content Filter Policies' `
        -Finding 'Unable to retrieve anti-spam policies to assess ZAP configuration' `
        -Recommendation 'Ensure the account has Security Reader or higher permissions.' `
        -ReferenceUrl 'https://aka.ms/mdo-zap' -ErrorMessage $_.ToString()
    return
}

$ruleByPolicy = @{}
foreach ($r in $spamRules) { $ruleByPolicy[$r.HostedContentFilterPolicy] = $r }

foreach ($policy in $spamPolicies) {
    $isDefault = $policy.IsDefault -eq $true
    $rule      = $ruleByPolicy[$policy.Name]

    if (-not $isDefault -and (-not $rule -or $rule.State -ne 'Enabled')) { continue }

    $scope = if ($isDefault) {
        'catch-all (default — applies to all uncovered recipients)'
    } else {
        Get-METRuleScope -Rule $rule
    }
    $label = "$($policy.Name) [$scope]"

    $issues = [System.Collections.Generic.List[string]]::new()

    if (-not $policy.ZapEnabled)      { $issues.Add('ZAP is disabled for this policy') }
    if (-not $policy.SpamZapEnabled)  { $issues.Add('ZAP for spam is disabled') }
    if (-not $policy.PhishZapEnabled) { $issues.Add('ZAP for phishing is disabled') }

    if ($issues.Count -gt 0) {
        New-METCheckResult -CheckId 'MET-MDO009' -Category MDO -Name 'Zero-Hour Auto Purge (ZAP)' `
            -Result Fail -Severity High -AffectedObject $label `
            -Finding ($issues -join '; ') `
            -Recommendation 'Enable ZAP (ZapEnabled), ZAP for spam (SpamZapEnabled), and ZAP for phishing (PhishZapEnabled) in all active anti-spam policies.' `
            -ReferenceUrl 'https://aka.ms/mdo-zap'
    }
    else {
        New-METCheckResult -CheckId 'MET-MDO009' -Category MDO -Name 'Zero-Hour Auto Purge (ZAP)' `
            -Result Pass -Severity High -AffectedObject $label `
            -Finding 'ZAP is enabled for spam and phishing' `
            -ReferenceUrl 'https://aka.ms/mdo-zap'
    }
}
