$issues = [System.Collections.Generic.List[string]]::new()

# ── Defender portal: report submission policy (Teams-specific properties) ─────
$submissionPolicy = $null
try {
    $submissionPolicy = Get-ReportSubmissionPolicy -ErrorAction Stop
}
catch {
    New-METCheckResult -CheckId 'MET-Teams005' -Category Teams -Name 'Teams User Reporting' `
        -Result Fail -Severity Medium -AffectedObject 'Teams User Reporting Settings' `
        -Finding 'Unable to retrieve report submission policy.' `
        -Recommendation 'Ensure the account has Security Reader or higher permissions.' `
        -ReferenceUrl 'https://aka.ms/mdo-teams-user-reporting' -ErrorMessage $_.ToString()
    return
}

if ($submissionPolicy) {
    if (-not $submissionPolicy.ReportChatMessageEnabled) {
        $issues.Add('"Monitor reported items in Microsoft Teams" is disabled in the Defender portal — Teams user reports are not monitored by the security team')
    }

    if ($submissionPolicy.ReportChatMessageEnabled -and -not $submissionPolicy.ReportChatMessageToCustomizedAddressEnabled) {
        $issues.Add('Teams reported messages are not copied to the SecOps mailbox — security team has no direct inbox visibility into Teams user reports')
    }
}

# ── Teams admin center: messaging policy ─────────────────────────────────────
# AllowSecurityEndUserReporting controls whether the "Report a security concern"
# button appears in the Teams client. Checked on all policies, not just Global,
# since per-user/group policy assignments can silently suppress the button.
try {
    $disabledPolicies = @(
        Get-CsTeamsMessagingPolicy -ErrorAction Stop |
        Where-Object {
            $null -ne $_.AllowSecurityEndUserReporting -and
            $_.AllowSecurityEndUserReporting -eq $false
        }
    )
    if ($disabledPolicies.Count -gt 0) {
        $names = ($disabledPolicies | Select-Object -ExpandProperty Identity) -join ', '
        $issues.Add("`"Report a security concern`" is disabled in the following Teams messaging policy/policies: $names — users assigned to these policies cannot flag suspicious messages")
    }
}
catch {
    Write-Verbose "Could not retrieve Teams messaging policies: $_"
}

if ($issues.Count -gt 0) {
    New-METCheckResult -CheckId 'MET-Teams005' -Category Teams -Name 'Teams User Reporting' `
        -Result Fail -Severity Medium -AffectedObject 'Teams User Reporting Settings' `
        -Finding ($issues -join '; ') `
        -Recommendation "1. In the Defender portal go to Settings > Email & collaboration > User reported settings and enable `"Monitor reported items in Microsoft Teams`" and route Teams reports to your SecOps mailbox.`n2. In the Teams admin center (admin.teams.microsoft.com) ensure `"Report a security concern`" is enabled in all active messaging policies." `
        -ReferenceUrl 'https://aka.ms/mdo-teams-user-reporting'
}
else {
    New-METCheckResult -CheckId 'MET-Teams005' -Category Teams -Name 'Teams User Reporting' `
        -Result Pass -Severity Medium -AffectedObject 'Teams User Reporting Settings' `
        -Finding 'Teams user reporting is enabled in the Defender portal, Teams reports are routed to the SecOps mailbox, and all Teams messaging policies allow users to report security concerns.' `
        -ReferenceUrl 'https://aka.ms/mdo-teams-user-reporting'
}
