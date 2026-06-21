try {
    $spamRules    = @(Get-HostedContentFilterRule    -ErrorAction Stop | Sort-Object Priority)
    $spamPolicies = @(Get-HostedContentFilterPolicy  -ErrorAction Stop)
}
catch {
    New-METCheckResult -CheckId 'MET-EXO008' -Category EXO -Name 'Quarantine Retention' `
        -Result Fail -Severity Low -AffectedObject 'Hosted Content Filter Policies' `
        -Finding 'Unable to retrieve anti-spam policies' `
        -Recommendation 'Ensure the account has Security Reader or higher permissions.' `
        -ReferenceUrl 'https://aka.ms/mdo-quarantine-retention' -ErrorMessage $_.ToString()
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
    $label     = "$($policy.Name) [$scope]"
    $retention = $policy.QuarantineRetentionPeriod

    if ($null -ne $retention -and $retention -lt 30) {
        New-METCheckResult -CheckId 'MET-EXO008' -Category EXO -Name 'Quarantine Retention' `
            -Result Fail -Severity Low -AffectedObject $label `
            -Finding "Quarantine retention period is $retention days — Microsoft recommends 30 days for Standard and Strict profiles" `
            -Recommendation "Run: Set-HostedContentFilterPolicy -Identity '$($policy.Name)' -QuarantineRetentionPeriod 30. A 30-day retention window gives end users and admins adequate time to review and release false positives before messages are purged." `
            -ReferenceUrl 'https://aka.ms/mdo-quarantine-retention'
    }
    else {
        New-METCheckResult -CheckId 'MET-EXO008' -Category EXO -Name 'Quarantine Retention' `
            -Result Pass -Severity Low -AffectedObject $label `
            -Finding "Quarantine retention period is $retention days" `
            -ReferenceUrl 'https://aka.ms/mdo-quarantine-retention'
    }
}
