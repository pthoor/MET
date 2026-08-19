try {
    $policies = Get-QuarantinePolicy -ErrorAction Stop
}
catch {
    New-METCheckResult -CheckId 'MET-EXO004' -Category EXO -Name 'Quarantine Policies' `
        -Result Fail -Severity Medium -AffectedObject 'Quarantine Policies' `
        -Finding 'Unable to retrieve quarantine policies' `
        -Recommendation 'Ensure the account has Security Reader or higher permissions.' `
        -ReferenceUrl 'https://aka.ms/mdo-quarantinepolicies' -ErrorMessage $_.ToString()
    return
}

$customPolicies = @($policies | Where-Object { -not (Test-METIsBuiltInQuarantinePolicyName -Name $_.Name) })

if ($customPolicies.Count -eq 0) {
    New-METCheckResult -CheckId 'MET-EXO004' -Category EXO -Name 'Quarantine Policies' `
        -Result Pass -Severity Medium -AffectedObject 'Quarantine Policies' `
        -Finding 'No custom quarantine policies exist - only the 4 Microsoft built-in policies (AdminOnlyAccessPolicy, DefaultFullAccessPolicy, DefaultFullAccessWithNotificationPolicy, NotificationEnabledPolicy) are present, nothing to review' `
        -ReferenceUrl 'https://aka.ms/mdo-quarantinepolicies'
    return
}

foreach ($policy in $customPolicies) {
    if (-not $policy.ESNEnabled -and $policy.EndUserQuarantinePermissionsValue -gt 0) {
        New-METCheckResult -CheckId 'MET-EXO004' -Category EXO -Name 'Quarantine Policies' `
            -Result Warning -Severity Medium -AffectedObject $policy.Name `
            -Finding 'End users are granted quarantine permissions (e.g. review, release, delete) but end-user spam notifications (ESN) are disabled, so they are never notified that anything is quarantined and have no way to know to use those permissions' `
            -Recommendation 'Enable end-user spam notifications (ESNEnabled) on this quarantine policy so users are alerted when they have messages to review, or remove their end-user permissions if notifications are intentionally disabled.' `
            -ReferenceUrl 'https://aka.ms/mdo-quarantinepolicies'
    }
    else {
        New-METCheckResult -CheckId 'MET-EXO004' -Category EXO -Name 'Quarantine Policies' `
            -Result Pass -Severity Medium -AffectedObject $policy.Name `
            -Finding 'Notification settings are consistent with the permissions granted to end users' `
            -ReferenceUrl 'https://aka.ms/mdo-quarantinepolicies'
    }
}
