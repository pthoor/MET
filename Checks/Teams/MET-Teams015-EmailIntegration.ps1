$referenceUrl = 'https://learn.microsoft.com/en-us/powershell/module/microsoftteams/set-csteamsclientconfiguration'

try {
    $clientConfig = Get-CsTeamsClientConfiguration -ErrorAction Stop
}
catch {
    New-METCheckResult -CheckId 'MET-Teams015' -Category Teams -Name 'Teams Email Integration' `
        -Result Fail -Severity Medium -AffectedObject 'Teams Client Configuration' `
        -Finding 'Unable to retrieve the Teams client configuration, so it could not be determined whether channel email integration is enabled.' `
        -Recommendation 'Ensure the MicrosoftTeams module is installed and the account has Teams administrator or higher permissions, then re-run this check.' `
        -ReferenceUrl $referenceUrl -ErrorMessage $_.ToString()
    return
}

$allowEmailIntoChannel = $clientConfig.AllowEmailIntoChannel

if ($null -eq $allowEmailIntoChannel) {
    New-METCheckResult -CheckId 'MET-Teams015' -Category Teams -Name 'Teams Email Integration' `
        -Result Warning -Severity Medium -AffectedObject 'Teams Client Configuration' `
        -Finding 'The AllowEmailIntoChannel property was absent from the Teams client configuration, so the state of channel email integration could not be confirmed. Because this setting governs a mail ingress path that bypasses mailbox delivery, it should not be assumed disabled and must be checked manually.' `
        -Recommendation 'Run Get-CsTeamsClientConfiguration and inspect AllowEmailIntoChannel. If channel email integration is not required, disable it tenant-wide with Set-CsTeamsClientConfiguration -Identity Global -AllowEmailIntoChannel $false. Where teams genuinely depend on it, leave it enabled and restrict inbound senders per team to a named accepted-domain list via the channel''s email address settings, then review which channels have addresses issued. Note that channel email addresses already issued are not revoked by disabling the setting, so existing addresses should be reviewed separately.' `
        -ReferenceUrl $referenceUrl
}
elseif ($allowEmailIntoChannel -eq $true) {
    New-METCheckResult -CheckId 'MET-Teams015' -Category Teams -Name 'Teams Email Integration' `
        -Result Warning -Severity Medium -AffectedObject 'Teams Client Configuration' `
        -Finding 'Channel email integration is enabled (AllowEmailIntoChannel is set to true) - any Teams channel can be issued an @<tenant>.teams.ms address that accepts mail from outside the organisation. Mail sent to that address is delivered into the channel conversation rather than to a mailbox, so Exchange transport rules and mailbox-level policy never apply to it, and the message lands in a space colleagues implicitly trust as internal. That makes it an attractive delivery route for a phishing payload or a lure that would have been filtered on the mail path. This is a legitimate and commonly-used feature, so the finding is the unmonitored ingress path it creates rather than the setting being inherently misconfigured.' `
        -Recommendation 'Run Set-CsTeamsClientConfiguration -Identity Global -AllowEmailIntoChannel $false to disable channel email integration tenant-wide. Where teams genuinely depend on it, leave it enabled and restrict inbound senders per team to a named accepted-domain list via the channel''s email address settings, then review which channels currently have addresses issued. Note that channel email addresses already issued are not revoked by disabling the setting, so existing addresses should be reviewed separately.' `
        -ReferenceUrl $referenceUrl
}
else {
    New-METCheckResult -CheckId 'MET-Teams015' -Category Teams -Name 'Teams Email Integration' `
        -Result Pass -Severity Medium -AffectedObject 'Teams Client Configuration' `
        -Finding 'Channel email integration is disabled (AllowEmailIntoChannel is set to false) - channels cannot be issued an email address, closing an ingress path that would deliver externally-sourced mail straight into a channel conversation without passing through Exchange transport rules or mailbox-level policy.' `
        -Recommendation 'No change required. Channel email addresses issued before the setting was disabled are not revoked automatically, so review whether any channels still hold an address.' `
        -ReferenceUrl $referenceUrl
}
