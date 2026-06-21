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

foreach ($policy in $policies) {
    $issues = [System.Collections.Generic.List[string]]::new()

    if ($policy.EndUserQuarantinePermissionsValue -eq 0) {
        $issues.Add('End-user quarantine permissions are set to none — users cannot review or release quarantined messages')
    }

    if (-not $policy.QuarantineRetentionDays -or $policy.QuarantineRetentionDays -lt 15) {
        $issues.Add("Quarantine retention is $($policy.QuarantineRetentionDays) days — recommended minimum is 15 days")
    }

    $isHighConfPhishPolicy = $policy.Name -match 'HighConfidencePhish|AdminOnlyAccess'
    if ($isHighConfPhishPolicy -and $policy.EndUserQuarantinePermissionsValue -gt 0) {
        $issues.Add('End-user self-release permissions are configured on a high-confidence phish quarantine policy — users should not be able to self-release phishing messages')
    }

    if ($issues.Count -gt 0) {
        New-METCheckResult -CheckId 'MET-EXO004' -Category EXO -Name 'Quarantine Policies' `
            -Result Warning -Severity Medium -AffectedObject $policy.Name `
            -Finding ($issues -join '; ') `
            -Recommendation 'Configure end-user quarantine notifications with review (but not self-release) permissions for high-confidence phish. Ensure retention is at least 15 days.' `
            -ReferenceUrl 'https://aka.ms/mdo-quarantinepolicies'
    }
    else {
        New-METCheckResult -CheckId 'MET-EXO004' -Category EXO -Name 'Quarantine Policies' `
            -Result Pass -Severity Medium -AffectedObject $policy.Name `
            -Finding 'Quarantine policy is appropriately configured' `
            -ReferenceUrl 'https://aka.ms/mdo-quarantinepolicies'
    }
}
