try {
    $outboundRules    = @(Get-HostedOutboundSpamFilterRule    -ErrorAction Stop | Sort-Object Priority)
    $outboundPolicies = @(Get-HostedOutboundSpamFilterPolicy  -ErrorAction Stop)
}
catch {
    New-METCheckResult -CheckId 'MET-MDO007' -Category MDO -Name 'Anti-Spam Outbound' `
        -Result Fail -Severity Medium -AffectedObject 'Outbound Spam Filter Policies' `
        -Finding 'Unable to retrieve outbound spam filter policies' `
        -Recommendation 'Ensure the account has Security Reader or higher permissions.' `
        -ReferenceUrl 'https://aka.ms/mdo-outboundspam' -ErrorMessage $_.ToString()
    return
}

$ruleByPolicy = @{}
foreach ($r in $outboundRules) { $ruleByPolicy[$r.HostedOutboundSpamFilterPolicy] = $r }

foreach ($policy in $outboundPolicies) {
    $isDefault = $policy.IsDefault -eq $true
    $rule      = $ruleByPolicy[$policy.Name]

    if (-not $isDefault -and (-not $rule -or $rule.State -ne 'Enabled')) { continue }

    $scope = if ($isDefault) {
        'catch-all (default — applies to all uncovered senders)'
    } else {
        Get-METRuleScope -Rule $rule
    }
    $label = "$($policy.Name) [$scope]"

    $issues = [System.Collections.Generic.List[string]]::new()

    if ($policy.AutoForwardingMode -ne 'Off') {
        $issues.Add("Auto-forwarding is '$($policy.AutoForwardingMode)' — should be 'Off' to prevent data exfiltration")
    }
    if ($policy.ActionWhenThresholdReached -eq 'Alert') {
        $issues.Add("Action when sending limit is reached is 'Alert' only — consider 'BlockUser' or 'BlockUserForToday'")
    }
    if ($policy.NotifyOutboundSpamRecipients.Count -eq 0) {
        $issues.Add('No admin notification address configured for outbound spam events')
    }

    if ($issues.Count -gt 0) {
        $result = if ($policy.AutoForwardingMode -ne 'Off') { 'Fail' } else { 'Warning' }
        New-METCheckResult -CheckId 'MET-MDO007' -Category MDO -Name 'Anti-Spam Outbound' `
            -Result $result -Severity Medium -AffectedObject $label `
            -Finding ($issues -join '; ') `
            -Recommendation "Disable auto-forwarding (set AutoForwardingMode to 'Off'), set action on limit breach to 'BlockUser', and configure an admin notification address." `
            -ReferenceUrl 'https://aka.ms/mdo-outboundspam'
    }
    else {
        New-METCheckResult -CheckId 'MET-MDO007' -Category MDO -Name 'Anti-Spam Outbound' `
            -Result Pass -Severity Medium -AffectedObject $label `
            -Finding 'Outbound spam filter policy is correctly configured' `
            -ReferenceUrl 'https://aka.ms/mdo-outboundspam'
    }
}
