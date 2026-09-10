$issues = [System.Collections.Generic.List[string]]::new()
$messagingPolicyError = $null

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

if (-not $submissionPolicy) {
    # Matches MET-EXO006's handling of the same cmdlet returning nothing without
    # throwing: an absent submission policy is a finding, not a silent skip.
    New-METCheckResult -CheckId 'MET-Teams005' -Category Teams -Name 'Teams User Reporting' `
        -Result Fail -Severity Medium -AffectedObject 'Teams User Reporting Settings' `
        -Finding 'No report submission policy found - Teams user reporting cannot be routed or monitored.' `
        -Recommendation 'In the Defender portal go to Settings > Email & collaboration > User reported settings and configure the reporting experience.' `
        -ReferenceUrl 'https://aka.ms/mdo-teams-user-reporting'
    return
}

if ($submissionPolicy) {
    if (-not $submissionPolicy.ReportChatMessageEnabled) {
        $issues.Add('"Monitor reported items in Microsoft Teams" is disabled in the Defender portal - Teams user reports are not monitored by the security team')
    }

    if ($submissionPolicy.ReportChatMessageEnabled -and -not $submissionPolicy.ReportChatMessageToCustomizedAddressEnabled) {
        $issues.Add('Teams reported messages are not copied to the SecOps mailbox - security team has no direct inbox visibility into Teams user reports')
    }
}

# ── Teams admin center: messaging policy ─────────────────────────────────────
# AllowSecurityEndUserReporting controls whether the "Report a security concern"
# button appears in the Teams client. Checked on all policies, not just Global,
# since per-user/group policy assignments can silently suppress the button.
$messagingPolicyUnreportedMessage = $null
try {
    $messagingPolicies = @(Get-CsTeamsMessagingPolicy -ErrorAction Stop)

    # A property must be present AND non-null to say anything about its value - a policy
    # that never returned AllowSecurityEndUserReporting, or returned it as $null, is
    # neither "enabled" nor "disabled", it is unobserved, so it is tracked separately
    # from $disabledPolicies rather than folded into the -eq $false filter below.
    $disabledPolicies = @(
        $messagingPolicies | Where-Object {
            $_.PSObject.Properties['AllowSecurityEndUserReporting'] -and
            $_.AllowSecurityEndUserReporting -eq $false
        }
    )
    $unreportedPolicies = @(
        $messagingPolicies | Where-Object {
            -not $_.PSObject.Properties['AllowSecurityEndUserReporting'] -or
            $null -eq $_.AllowSecurityEndUserReporting
        }
    )

    if ($disabledPolicies.Count -gt 0) {
        $names = ($disabledPolicies | Select-Object -ExpandProperty Identity) -join ', '
        $issues.Add("`"Report a security concern`" is disabled in the following Teams messaging policy/policies: $names - users assigned to these policies cannot flag suspicious messages")
    }

    if ($messagingPolicies.Count -eq 0) {
        $messagingPolicyUnreportedMessage = 'Get-CsTeamsMessagingPolicy returned no Teams messaging policies, so whether the "Report a security concern" button is enabled for any user was not established.'
        $messagingPolicyUnreportedErrorMessage = 'Get-CsTeamsMessagingPolicy returned no Teams messaging policies.'
    }
    elseif ($unreportedPolicies.Count -gt 0) {
        $unreportedNames = ($unreportedPolicies | Select-Object -ExpandProperty Identity) -join ', '
        $messagingPolicyUnreportedMessage = "AllowSecurityEndUserReporting was not returned for the following Teams messaging policy/policies: $unreportedNames - whether the `"Report a security concern`" button is enabled for users assigned to them was not established."
        $messagingPolicyUnreportedErrorMessage = "AllowSecurityEndUserReporting was not returned by Get-CsTeamsMessagingPolicy for the following Teams messaging policy/policies: $unreportedNames."
    }
}
catch {
    # The Pass wording below asserts that every Teams messaging policy allows security
    # reporting. If this leg could not run - MicrosoftTeams absent or not connected,
    # which is a supported configuration - that assertion is unverified, so the check
    # must not claim it. Record the gap instead of swallowing it.
    Write-Verbose "Could not retrieve Teams messaging policies: $_"
    $messagingPolicyError = $_.ToString()
}

if ($messagingPolicyUnreportedMessage -and $issues.Count -gt 0) {
    $issues.Add($messagingPolicyUnreportedMessage)
}

# A confirmed Defender-portal failure must not swallow a Teams-side retrieval failure on
# a different control - the reader still needs to know that leg was never assessed,
# marked as unverified rather than a second confirmed failure.
$failErrorMessage = $null
if ($messagingPolicyError -and $issues.Count -gt 0) {
    $issues.Add("Additionally, the Teams messaging policies could not be retrieved, so whether every user can report a security concern is unverified rather than a confirmed failure: $messagingPolicyError")
    $failErrorMessage = $messagingPolicyError
}

if ($issues.Count -gt 0) {
    New-METCheckResult -CheckId 'MET-Teams005' -Category Teams -Name 'Teams User Reporting' `
        -Result Fail -Severity Medium -AffectedObject 'Teams User Reporting Settings' `
        -Finding ($issues -join '; ') `
        -Recommendation "1. In the Defender portal go to Settings > Email & collaboration > User reported settings and enable `"Monitor reported items in Microsoft Teams`" and route Teams reports to your SecOps mailbox.`n2. In the Teams admin center (admin.teams.microsoft.com) ensure `"Report a security concern`" is enabled in all active messaging policies." `
        -ReferenceUrl 'https://aka.ms/mdo-teams-user-reporting' `
        -ErrorMessage $failErrorMessage
}
elseif ($messagingPolicyError) {
    New-METCheckResult -CheckId 'MET-Teams005' -Category Teams -Name 'Teams User Reporting' `
        -Result Warning -Severity Medium -AffectedObject 'Teams User Reporting Settings' `
        -Finding 'Teams user reporting is correctly configured in the Defender portal, but the Teams messaging policies could not be read, so whether the "Report a security concern" button is enabled for all users is unverified.' `
        -Recommendation 'Connect the MicrosoftTeams module (Connect-METSession without -SkipTeams) and rerun, or confirm "Report a security concern" is enabled in every messaging policy in the Teams admin center.' `
        -ReferenceUrl 'https://aka.ms/mdo-teams-user-reporting' -ErrorMessage $messagingPolicyError
}
elseif ($messagingPolicyUnreportedMessage) {
    New-METCheckResult -CheckId 'MET-Teams005' -Category Teams -Name 'Teams User Reporting' `
        -Result Warning -Severity Medium -AffectedObject 'Teams User Reporting Settings' `
        -Finding "Teams user reporting is correctly configured in the Defender portal, but $messagingPolicyUnreportedMessage An unconfirmed state is reported as unassessed rather than a pass, because nothing here distinguishes a tenant where every user can report a security concern from one where some cannot." `
        -Recommendation 'Confirm "Report a security concern" is enabled for every Teams messaging policy directly in the Teams admin center (admin.teams.microsoft.com), or update MicrosoftTeams to a version that returns AllowSecurityEndUserReporting from Get-CsTeamsMessagingPolicy and rerun.' `
        -ReferenceUrl 'https://aka.ms/mdo-teams-user-reporting' `
        -ErrorMessage $messagingPolicyUnreportedErrorMessage
}
else {
    New-METCheckResult -CheckId 'MET-Teams005' -Category Teams -Name 'Teams User Reporting' `
        -Result Pass -Severity Medium -AffectedObject 'Teams User Reporting Settings' `
        -Finding 'Teams user reporting is enabled in the Defender portal, Teams reports are routed to the SecOps mailbox, and all Teams messaging policies allow users to report security concerns.' `
        -ReferenceUrl 'https://aka.ms/mdo-teams-user-reporting'
}
