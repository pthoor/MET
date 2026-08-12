$issues = [System.Collections.Generic.List[string]]::new()

# Check Teams guest messaging configuration
try {
    $guestMsg = Get-CsTeamsGuestMessagingConfiguration -ErrorAction Stop
    if ($guestMsg.AllowUserChat -eq $true) {
        $issues.Add('Guests are allowed to initiate 1:1 chat with staff — widens the social-engineering surface for guest-account-based attacks')
    }
}
catch {
    $issues.Add("Could not retrieve Teams guest messaging configuration: $($_.Exception.Message)")
    Write-Verbose "Could not retrieve Teams guest messaging configuration: $_"
}

# Check Teams guest calling configuration
try {
    $guestCall = Get-CsTeamsGuestCallingConfiguration -ErrorAction Stop
    if ($guestCall.AllowPrivateCalling -eq $true) {
        $issues.Add('Guests are allowed to make private (1:1) calls to staff — an additional social-engineering/vishing vector via guest accounts')
    }
}
catch {
    $issues.Add("Could not retrieve Teams guest calling configuration: $($_.Exception.Message)")
    Write-Verbose "Could not retrieve Teams guest calling configuration: $_"
}

if ($issues.Count -gt 0) {
    New-METCheckResult -CheckId 'MET-Teams007' -Category Teams -Name 'Guest Messaging/Calling Configuration' `
        -Result Warning -Severity Medium -AffectedObject 'Teams Guest Configuration' `
        -Finding ($issues -join '; ') `
        -Recommendation 'If guest access is enabled at all for this tenant, consider whether guests need chat-initiation and private-calling rights specifically, distinct from meeting participation. Disable AllowUserChat and AllowPrivateCalling for guest configurations unless there is a specific collaboration need — this is separate from meeting-level controls (see MET-Teams003) and from external tenant federation (see MET-Teams006). Run: Set-CsTeamsGuestMessagingConfiguration -AllowUserChat $false and Set-CsTeamsGuestCallingConfiguration -AllowPrivateCalling $false to restrict.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/teams/get-csteamsguestmessagingconfiguration'
}
else {
    New-METCheckResult -CheckId 'MET-Teams007' -Category Teams -Name 'Guest Messaging/Calling Configuration' `
        -Result Pass -Severity Medium -AffectedObject 'Teams Guest Configuration' `
        -Finding 'Teams guest messaging and calling configuration does not allow guest-initiated chat or private calling' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/teams/get-csteamsguestmessagingconfiguration'
}
