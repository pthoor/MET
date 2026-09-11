[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'METCheckInfo',
    Justification = 'Check metadata. Read from the AST by Get-METCheck and never executed.')]
param()

$METCheckInfo = @{
    Name           = 'Safe Attachments for Teams'
    Severity       = 'High'
    Description    = 'Verifies EnableATPForSPOTeamsODB on Get-AtpPolicyForO365, the sole documented toggle for Safe Attachments protection in SharePoint, OneDrive, and Teams.'
    RequiresModule = @('ExchangeOnlineManagement')
}

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

if (-not $atpGlobal -or -not $atpGlobal.PSObject.Properties['EnableATPForSPOTeamsODB'] -or $null -eq $atpGlobal.EnableATPForSPOTeamsODB) {
    New-METCheckResult -CheckId 'MET-Teams002' -Category Teams -Name 'Safe Attachments for Teams' `
        -Result NotApplicable -Severity High -AffectedObject 'Global Safe Attachments Settings' `
        -Finding 'The EnableATPForSPOTeamsODB property was not returned by the global Safe Attachments policy, so whether Safe Attachments protects files shared via Teams was not established. An unconfirmed state is reported as unassessed rather than a pass, because nothing here distinguishes a tenant with the setting on from one with it switched off.' `
        -Recommendation 'Confirm the setting directly with: Get-AtpPolicyForO365 | Format-List EnableATPForSPOTeamsODB. An absent property usually means an ExchangeOnlineManagement version that does not expose it - update the module and rerun the assessment.' `
        -ReferenceUrl 'https://aka.ms/mdo-safeattachments-teams' `
        -ErrorMessage 'The global Safe Attachments policy did not return an EnableATPForSPOTeamsODB value.'
}
elseif ($atpGlobal.EnableATPForSPOTeamsODB) {
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
