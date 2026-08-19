try {
    $atpGlobal = Get-AtpPolicyForO365 -ErrorAction Stop
}
catch {
    New-METCheckResult -CheckId 'MET-Teams002' -Category Teams -Name 'Safe Attachments for Teams' `
        -Result Fail -Severity High -AffectedObject 'Global Safe Attachments Settings' `
        -Finding 'Unable to retrieve the global Safe Attachments for SharePoint, OneDrive, and Teams setting' `
        -Recommendation 'Ensure the account has Security Reader or higher permissions.' `
        -ReferenceUrl 'https://aka.ms/mdo-safeattachments-teams' -ErrorMessage $_.ToString()
    return
}

if ($atpGlobal.EnableATPForSPOTeamsODB) {
    New-METCheckResult -CheckId 'MET-Teams002' -Category Teams -Name 'Safe Attachments for Teams' `
        -Result Pass -Severity High -AffectedObject 'Global Safe Attachments Settings' `
        -Finding 'Safe Attachments for SharePoint, OneDrive, and Microsoft Teams is enabled (EnableATPForSPOTeamsODB = $true)' `
        -ReferenceUrl 'https://aka.ms/mdo-safeattachments-teams'
}
else {
    New-METCheckResult -CheckId 'MET-Teams002' -Category Teams -Name 'Safe Attachments for Teams' `
        -Result Fail -Severity High -AffectedObject 'Global Safe Attachments Settings' `
        -Finding 'Safe Attachments for SharePoint, OneDrive, and Microsoft Teams is disabled (EnableATPForSPOTeamsODB = $false) - files shared via Teams are not scanned' `
        -Recommendation 'Run: Set-AtpPolicyForO365 -EnableATPForSPOTeamsODB $true' `
        -ReferenceUrl 'https://aka.ms/mdo-safeattachments-teams'
}
