$issues = [System.Collections.Generic.List[string]]::new()

try {
    $disabledPolicies = @(
        Get-CsTeamsCallingPolicy -ErrorAction Stop |
        Where-Object {
            $null -ne $_.ReportCall -and
            $_.ReportCall -ne 'Enabled'
        }
    )
}
catch {
    New-METCheckResult -CheckId 'MET-Teams012' -Category Teams -Name 'Call Reporting' `
        -Result Fail -Severity Medium -AffectedObject 'Teams Calling Policies' `
        -Finding 'Unable to retrieve Teams calling policies.' `
        -Recommendation 'Ensure the account has Teams administrator or higher permissions.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/microsoftteams/new-csteamscallingpolicy' -ErrorMessage $_.ToString()
    return
}

if ($disabledPolicies.Count -gt 0) {
    $names = ($disabledPolicies | Select-Object -ExpandProperty Identity) -join ', '
    $issues.Add("Call reporting (ReportCall) is disabled in the following Teams calling policy/policies: $names - users assigned to these policies cannot report a suspicious call, such as a helpdesk-vishing attempt")
}

if ($issues.Count -gt 0) {
    New-METCheckResult -CheckId 'MET-Teams012' -Category Teams -Name 'Call Reporting' `
        -Result Fail -Severity Medium -AffectedObject 'Teams Calling Policies' `
        -Finding ($issues -join '; ') `
        -Recommendation 'Set-CsTeamsCallingPolicy -Identity <name> -ReportCall Enabled' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/microsoftteams/new-csteamscallingpolicy'
}
else {
    New-METCheckResult -CheckId 'MET-Teams012' -Category Teams -Name 'Call Reporting' `
        -Result Pass -Severity Medium -AffectedObject 'Teams Calling Policies' `
        -Finding 'Call reporting is enabled in all Teams calling policies, allowing users to report suspicious calls such as helpdesk-vishing attempts.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/microsoftteams/new-csteamscallingpolicy'
}
