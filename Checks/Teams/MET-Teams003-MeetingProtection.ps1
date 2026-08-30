$issues = [System.Collections.Generic.List[string]]::new()

# Check Teams external access settings via EXO/Graph
try {
    $tenantConfig = Get-CsTenantFederationConfiguration -ErrorAction Stop
    if ($tenantConfig.AllowFederatedUsers -eq $false) {
        $issues.Add('External access (federation) is fully disabled - may impact legitimate collaboration')
    }
    if ($tenantConfig.AllowPublicUsers -eq $true) {
        $issues.Add('Access from Skype consumer users is allowed - consider disabling if not needed')
    }
}
catch {
    $issues.Add("Could not retrieve tenant federation configuration: $($_.Exception.Message)")
    Write-Verbose "Could not retrieve tenant federation configuration: $_"
}

# Check Teams meeting policies for anonymous join and lobby settings. Every
# policy instance is evaluated, not just Global, since per-user/group policy
# assignments can silently apply weaker settings than the tenant default.
try {
    $meetingPolicies = @(Get-CsTeamsMeetingPolicy -ErrorAction Stop)

    $anonymousJoinPolicies = @($meetingPolicies | Where-Object { $_.AllowAnonymousUsersToJoinMeeting -eq $true })
    if ($anonymousJoinPolicies.Count -gt 0) {
        $names = ($anonymousJoinPolicies | Select-Object -ExpandProperty Identity) -join ', '
        $issues.Add("Anonymous users are allowed to join meetings without being admitted from the lobby in the following meeting policy/policies: $names")
    }

    $everyoneAdmittedPolicies = @($meetingPolicies | Where-Object { $_.AutoAdmittedUsers -eq 'Everyone' })
    if ($everyoneAdmittedPolicies.Count -gt 0) {
        $names = ($everyoneAdmittedPolicies | Select-Object -ExpandProperty Identity) -join ', '
        $issues.Add("AutoAdmittedUsers is 'Everyone' in the following meeting policy/policies: $names - all users bypass the lobby; recommended: 'EveryoneInSameAndFederatedCompany' or stricter")
    }

    $externalChatPolicies = @($meetingPolicies | Where-Object { $_.AllowExternalNonTrustedMeetingChat -eq $true })
    if ($externalChatPolicies.Count -gt 0) {
        $names = ($externalChatPolicies | Select-Object -ExpandProperty Identity) -join ', '
        $issues.Add("External non-trusted participants are allowed to use meeting chat in the following meeting policy/policies: $names")
    }

    $pstnLobbyBypassPolicies = @($meetingPolicies | Where-Object { $_.AllowPSTNUsersToBypassLobby -eq $true })
    if ($pstnLobbyBypassPolicies.Count -gt 0) {
        $names = ($pstnLobbyBypassPolicies | Select-Object -ExpandProperty Identity) -join ', '
        $issues.Add("PSTN callers bypass the lobby in the following meeting policy/policies: $names - phone participants are automatically admitted, a meeting-invite-lure risk")
    }

    $giveControlPolicies = @($meetingPolicies | Where-Object { $_.AllowExternalParticipantGiveRequestControl -eq $true })
    if ($giveControlPolicies.Count -gt 0) {
        $names = ($giveControlPolicies | Select-Object -ExpandProperty Identity) -join ', '
        $issues.Add("External participants can request and be granted control of a shared screen in the following meeting policy/policies: $names - the screen-control handoff used in helpdesk-impersonation and remote-access social engineering")
    }

    $anonymousStartPolicies = @($meetingPolicies | Where-Object { $_.AllowAnonymousUsersToStartMeeting -eq $true })
    if ($anonymousStartPolicies.Count -gt 0) {
        $names = ($anonymousStartPolicies | Select-Object -ExpandProperty Identity) -join ', '
        $issues.Add("Anonymous (unauthenticated) participants can start a meeting with no organiser present in the following meeting policy/policies: $names - this defeats lobby controls that assume an organiser is there to admit attendees")
    }
}
catch {
    $issues.Add("Could not retrieve Teams meeting policies: $($_.Exception.Message)")
    Write-Verbose "Could not retrieve Teams meeting policies: $_"
}

# Check Teams channel meeting policy
try {
    $channelMeetingPolicy = Get-CsTeamsChannelsPolicy -ErrorAction Stop | Where-Object { $_.Identity -eq 'Global' }
    if ($channelMeetingPolicy -and $channelMeetingPolicy.AllowSharedChannelCreation -eq $true) {
        # Shared channels bypass some external access controls - informational
        Write-Verbose 'Shared channel creation is enabled - ensure external sharing is reviewed in shared channels.'
    }
}
catch {
    $issues.Add("Could not retrieve Teams channel policy: $($_.Exception.Message)")
    Write-Verbose "Could not retrieve Teams channel policy: $_"
}

if ($issues.Count -gt 0) {
    $result = if ($issues | Where-Object { $_ -match 'Anonymous' -or $_ -match 'Everyone' -or $_ -match 'PSTN callers bypass the lobby' }) { 'Fail' } else { 'Warning' }
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
