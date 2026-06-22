$issues = [System.Collections.Generic.List[string]]::new()

# Check Teams external access settings via EXO/Graph
try {
    $tenantConfig = Get-CsTenantFederationConfiguration -ErrorAction Stop
    if ($tenantConfig.AllowFederatedUsers -eq $false) {
        $issues.Add('External access (federation) is fully disabled — may impact legitimate collaboration')
    }
    if ($tenantConfig.AllowPublicUsers -eq $true) {
        $issues.Add('Access from Skype consumer users is allowed — consider disabling if not needed')
    }
}
catch {
    $issues.Add("Unable to retrieve tenant federation configuration: $($_.Exception.Message)")
}

# Check Teams meeting policy for anonymous join and lobby settings
try {
    $meetingPolicies = Get-CsTeamsMeetingPolicy -ErrorAction Stop
    $globalPolicy    = $meetingPolicies | Where-Object { $_.Identity -eq 'Global' } | Select-Object -First 1

    if ($globalPolicy) {
        if ($globalPolicy.AllowAnonymousUsersToJoinMeeting -eq $true) {
            $issues.Add('Anonymous users are allowed to join meetings without being admitted from the lobby')
        }
        if ($globalPolicy.AutoAdmittedUsers -eq 'Everyone') {
            $issues.Add("AutoAdmittedUsers is 'Everyone' — all users bypass the lobby; recommended: 'EveryoneInSameAndFederatedCompany' or stricter")
        }
        if ($globalPolicy.AllowExternalNonTrustedMeetingChat -eq $true) {
            $issues.Add('External non-trusted participants are allowed to use meeting chat')
        }
    }
}
catch {
    Write-Verbose "Could not retrieve Teams meeting policies: $_"
}

# Check Teams channel meeting policy
try {
    $channelMeetingPolicy = Get-CsTeamsChannelsPolicy -ErrorAction Stop | Where-Object { $_.Identity -eq 'Global' }
    if ($channelMeetingPolicy -and $channelMeetingPolicy.AllowSharedChannelCreation -eq $true) {
        # Shared channels bypass some external access controls — informational
        Write-Verbose 'Shared channel creation is enabled — ensure external sharing is reviewed in shared channels.'
    }
}
catch {
    Write-Verbose "Could not retrieve Teams channel policy: $_"
}

if ($issues.Count -gt 0) {
    $result = if ($issues | Where-Object { $_ -match 'Anonymous' -or $_ -match 'Everyone' }) { 'Fail' } else { 'Warning' }
    New-METCheckResult -CheckId 'MET-Teams003' -Category Teams -Name 'Meeting Protection' `
        -Result $result -Severity Medium -AffectedObject 'Teams Meeting Policies' `
        -Finding ($issues -join '; ') `
        -Recommendation "Disable anonymous meeting join, set AutoAdmittedUsers to 'EveryoneInSameAndFederatedCompany' or 'OrganizerOnly', and review external chat permissions. Use the lobby as a security control." `
        -ReferenceUrl 'https://aka.ms/teams-meeting-security'
}
else {
    New-METCheckResult -CheckId 'MET-Teams003' -Category Teams -Name 'Meeting Protection' `
        -Result Pass -Severity Medium -AffectedObject 'Teams Meeting Policies' `
        -Finding 'Teams meeting protection settings are correctly configured' `
        -ReferenceUrl 'https://aka.ms/teams-meeting-security'
}
