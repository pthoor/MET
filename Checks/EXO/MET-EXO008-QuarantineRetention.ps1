[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'METCheckInfo',
    Justification = 'Check metadata. Read from the AST by Get-METCheck and never executed.')]
param()

$METCheckInfo = @{
    Name           = 'Quarantine Retention'
    Severity       = 'Low'
    Description    = 'Verifies QuarantineRetentionPeriod is at least 30 days in default and custom anti-spam policies.'
    RequiresModule = @('ExchangeOnlineManagement')
}

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

$antiPhishNote = 'This same retention value also governs anti-phishing quarantine (spoof/impersonation) for the same recipients - there is no separate anti-phish retention setting.'

foreach ($policy in $spamPolicies) {
    $isDefault = $policy.IsDefault -eq $true
    $rule      = $ruleByPolicy[$policy.Name]

    if (-not $isDefault -and (-not $rule -or $rule.State -ne 'Enabled')) { continue }

    $presetTier = Get-METPresetSecurityPolicyTier -Name $policy.Name
    $isPreset = [bool]$presetTier

    $scope = if ($isDefault) {
        'catch-all (default - applies to all uncovered recipients)'
    } elseif ($isPreset) {
        "$presetTier preset security policy"
    } else {
        Get-METRuleScope -Rule $rule
    }
    $label     = "$($policy.Name) [$scope]"
    $retention = $policy.QuarantineRetentionPeriod

    if ($null -eq $retention) {
        New-METCheckResult -CheckId 'MET-EXO008' -Category EXO -Name 'Quarantine Retention' `
            -Result Warning -Severity Low -AffectedObject $label `
            -Finding "The QuarantineRetentionPeriod property was not returned for this policy, so its quarantine retention window was not established. An unconfirmed state is reported as a gap rather than a pass, because nothing here distinguishes a policy at the recommended 30 days from one left at the 15-day default. $antiPhishNote" `
            -Recommendation "Confirm the value directly: Get-HostedContentFilterPolicy -Identity '$($policy.Name)' | Format-List QuarantineRetentionPeriod." `
            -ReferenceUrl 'https://aka.ms/mdo-quarantine-retention'
        continue
    }

    if ($isPreset) {
        if ($retention -lt 30) {
            New-METCheckResult -CheckId 'MET-EXO008' -Category EXO -Name 'Quarantine Retention' `
                -Result Warning -Severity Low -AffectedObject $label `
                -Finding "Quarantine retention period is $retention days, below the 30-day value Microsoft guarantees for $presetTier preset security policies. $antiPhishNote" `
                -Recommendation "Preset-generated policies are Microsoft-managed and not editable - Set-HostedContentFilterPolicy will error against '$($policy.Name)'. Treat this as an unexpected Microsoft-side anomaly to investigate (e.g. via a support request), not an admin misconfiguration to remediate." `
                -ReferenceUrl 'https://aka.ms/mdo-quarantine-retention'
        }
        else {
            New-METCheckResult -CheckId 'MET-EXO008' -Category EXO -Name 'Quarantine Retention' `
                -Result Pass -Severity Low -AffectedObject $label `
                -Finding "Quarantine retention period is $retention days, fixed by the $presetTier preset security policy and not admin-configurable. $antiPhishNote" `
                -ReferenceUrl 'https://aka.ms/mdo-quarantine-retention'
        }
        continue
    }

    if ($retention -lt 30) {
        New-METCheckResult -CheckId 'MET-EXO008' -Category EXO -Name 'Quarantine Retention' `
            -Result Fail -Severity Low -AffectedObject $label `
            -Finding "Quarantine retention period is $retention days - Microsoft recommends 30 days for Standard and Strict profiles. $antiPhishNote" `
            -Recommendation "Run: Set-HostedContentFilterPolicy -Identity '$($policy.Name)' -QuarantineRetentionPeriod 30. A 30-day retention window gives end users and admins adequate time to review and release false positives before messages are purged." `
            -ReferenceUrl 'https://aka.ms/mdo-quarantine-retention'
    }
    else {
        New-METCheckResult -CheckId 'MET-EXO008' -Category EXO -Name 'Quarantine Retention' `
            -Result Pass -Severity Low -AffectedObject $label `
            -Finding "Quarantine retention period is $retention days. $antiPhishNote" `
            -ReferenceUrl 'https://aka.ms/mdo-quarantine-retention'
    }
}
