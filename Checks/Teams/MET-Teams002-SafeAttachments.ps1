try {
    $atpGlobal = Get-AtpPolicyForO365 -ErrorAction Stop
    if (-not $atpGlobal.EnableATPForSPOTeamsODB) {
        New-METCheckResult -CheckId 'MET-Teams002' -Category Teams -Name 'Safe Attachments for Teams' `
            -Result Fail -Severity High -AffectedObject 'Global Safe Attachments Settings' `
            -Finding 'The global Safe Attachments toggle for SharePoint, OneDrive, and Microsoft Teams is disabled (EnableATPForSPOTeamsODB = $false) — per-policy settings have no effect' `
            -Recommendation 'Run: Set-AtpPolicyForO365 -EnableATPForSPOTeamsODB $true. This is a prerequisite for Safe Attachments to protect Teams file sharing regardless of per-policy configuration.' `
            -ReferenceUrl 'https://aka.ms/mdo-safeattachments-teams'
        return
    }
}
catch {
    Write-Verbose "Could not retrieve ATP global policy for O365: $_"
}

try {
    $policies = Get-SafeAttachmentPolicy -ErrorAction Stop
}
catch {
    New-METCheckResult -CheckId 'MET-Teams002' -Category Teams -Name 'Safe Attachments for Teams' `
        -Result Fail -Severity High -AffectedObject 'Safe Attachment Policies' `
        -Finding 'Unable to retrieve Safe Attachment policies' `
        -Recommendation 'Ensure the account has Security Reader or higher permissions.' `
        -ReferenceUrl 'https://aka.ms/mdo-safeattachments-teams' -ErrorMessage $_.ToString()
    return
}

if (-not $policies) {
    New-METCheckResult -CheckId 'MET-Teams002' -Category Teams -Name 'Safe Attachments for Teams' `
        -Result Fail -Severity High -AffectedObject 'Safe Attachment Policies' `
        -Finding 'No Safe Attachment policies found' `
        -Recommendation 'Create a Safe Attachments policy with EnableSafeAttachmentsForTeams enabled.' `
        -ReferenceUrl 'https://aka.ms/mdo-safeattachments-teams'
    return
}

$teamsEnabled = $policies | Where-Object { $_.EnableSafeAttachmentsForTeams -eq $true }

if (-not $teamsEnabled) {
    New-METCheckResult -CheckId 'MET-Teams002' -Category Teams -Name 'Safe Attachments for Teams' `
        -Result Fail -Severity High -AffectedObject 'Safe Attachment Policies' `
        -Finding 'No Safe Attachment policy has EnableSafeAttachmentsForTeams enabled — Teams file sharing is not scanned' `
        -Recommendation 'Enable EnableSafeAttachmentsForTeams in at least one Safe Attachments policy covering Teams users. This protects against malicious files shared via Teams channels and chats.' `
        -ReferenceUrl 'https://aka.ms/mdo-safeattachments-teams'
    return
}

foreach ($policy in $teamsEnabled) {
    New-METCheckResult -CheckId 'MET-Teams002' -Category Teams -Name 'Safe Attachments for Teams' `
        -Result Pass -Severity High -AffectedObject $policy.Name `
        -Finding 'Safe Attachments for Teams is enabled' `
        -ReferenceUrl 'https://aka.ms/mdo-safeattachments-teams'
}
