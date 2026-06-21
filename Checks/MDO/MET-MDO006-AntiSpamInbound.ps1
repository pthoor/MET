try {
    $spamRules    = @(Get-HostedContentFilterRule    -ErrorAction Stop | Sort-Object Priority)
    $spamPolicies = @(Get-HostedContentFilterPolicy  -ErrorAction Stop)
}
catch {
    New-METCheckResult -CheckId 'MET-MDO006' -Category MDO -Name 'Anti-Spam Inbound' `
        -Result Fail -Severity Medium -AffectedObject 'Hosted Content Filter Policies' `
        -Finding 'Unable to retrieve inbound anti-spam policies' `
        -Recommendation 'Ensure the account has Security Reader or higher permissions.' `
        -ReferenceUrl 'https://aka.ms/mdo-antispam' -ErrorMessage $_.ToString()
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

    if ($policy.SpamAction -eq 'AddXHeader' -or $policy.SpamAction -eq 'NoAction') {
        $issues.Add("Spam action is '$($policy.SpamAction)' — should be 'MoveToJmf' or 'Quarantine'")
    }
    if ($policy.HighConfidenceSpamAction -notin 'MoveToJmf','Quarantine') {
        $issues.Add("High-confidence spam action is '$($policy.HighConfidenceSpamAction)' — should be 'MoveToJmf' or 'Quarantine'")
    }
    if ($policy.PhishSpamAction -notin 'MoveToJmf','Quarantine') {
        $issues.Add("Phish action is '$($policy.PhishSpamAction)' — should be 'MoveToJmf' or 'Quarantine'")
    }
    if ($policy.HighConfidencePhishAction -ne 'Quarantine') {
        $issues.Add("High-confidence phish action is '$($policy.HighConfidencePhishAction)' — should be 'Quarantine'")
    }
    if ($policy.BulkThreshold -gt 6) {
        $issues.Add("Bulk complaint level (BCL) threshold is $($policy.BulkThreshold) — recommended 6 or lower")
    }

    # High-confidence phish must use AdminOnlyAccessPolicy so users cannot self-release these messages
    $hcpTag = $policy.HighConfidencePhishQuarantineTag
    if ($hcpTag -and $hcpTag -ne 'AdminOnlyAccessPolicy') {
        $issues.Add("High-confidence phish quarantine policy is '$hcpTag' — should be 'AdminOnlyAccessPolicy' to prevent self-release")
    }

    if ($issues.Count -gt 0) {
        New-METCheckResult -CheckId 'MET-MDO006' -Category MDO -Name 'Anti-Spam Inbound' `
            -Result Fail -Severity Medium -AffectedObject $label `
            -Finding ($issues -join '; ') `
            -Recommendation 'Set spam and high-confidence spam actions to MoveToJmf or Quarantine. Set high-confidence phish to Quarantine with AdminOnlyAccessPolicy so users cannot self-release phish. Lower BCL threshold to 6 or below.' `
            -ReferenceUrl 'https://aka.ms/mdo-antispam'
    }
    else {
        New-METCheckResult -CheckId 'MET-MDO006' -Category MDO -Name 'Anti-Spam Inbound' `
            -Result Pass -Severity Medium -AffectedObject $label `
            -Finding 'Inbound anti-spam policy is correctly configured' `
            -ReferenceUrl 'https://aka.ms/mdo-antispam'
    }
}
