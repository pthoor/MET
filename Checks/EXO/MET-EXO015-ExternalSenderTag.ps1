# Get-ExternalInOutlook hit the same generic server-side error as
# Get-ExoPhishSimOverrideRule/Get-ExoSecOpsOverrideRule when -ErrorAction is
# bound explicitly (see MET-EXO014 for the confirmed root cause). Use
# $ErrorActionPreference instead of the -ErrorAction parameter.
$previousErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = 'Stop'
try {
    $config = Get-ExternalInOutlook
}
catch {
    New-METCheckResult -CheckId 'MET-EXO015' -Category EXO -Name 'External Sender Warning Tag' `
        -Result Fail -Severity Medium -AffectedObject 'External Sender Tag Configuration' `
        -Finding 'Unable to retrieve external sender tag configuration' `
        -Recommendation 'This check already avoids the known ExchangeOnlineManagement bug where binding -ErrorAction on certain REST cmdlets causes a spurious generic server-side error (https://learn.microsoft.com/answers/a/1859386) - a failure here is more likely a genuine issue. Confirm the account holds View-Only Organization Management or Organization Management (Exchange Online RBAC), which govern read access to organization configuration. If permissions are correct, retry with a fresh Connect-ExchangeOnline session before ruling out a transient Microsoft-side issue.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-externalinoutlook' -ErrorMessage $_.ToString()
    return
}
finally {
    $ErrorActionPreference = $previousErrorActionPreference
}

if ($config.Enabled -eq $true) {
    if ($config.AllowList -and $config.AllowList.Count -gt 0) {
        $finding = "External sender tagging is enabled. $($config.AllowList.Count) sender(s)/domain(s) are exempted from the tag via the allow list."
    }
    else {
        $finding = 'External sender tagging is enabled - users see an "External" indicator on mail from outside the organization'
    }

    New-METCheckResult -CheckId 'MET-EXO015' -Category EXO -Name 'External Sender Warning Tag' `
        -Result Pass -Severity Medium -AffectedObject 'External Sender Tag Configuration' `
        -Finding $finding `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-externalinoutlook'
}
else {
    New-METCheckResult -CheckId 'MET-EXO015' -Category EXO -Name 'External Sender Warning Tag' `
        -Result Warning -Severity Medium -AffectedObject 'External Sender Tag Configuration' `
        -Finding 'External sender tagging is disabled - Outlook does not visually flag mail from outside the organization, removing a cheap, user-facing signal against lookalike-domain and BEC-style impersonation' `
        -Recommendation 'Run: Set-ExternalInOutlook -Enabled $true. This adds a native "External" tag to the sender area in Outlook (desktop, web, mobile) for mail from outside the organization, helping users spot spoofed or lookalike senders at a glance. Takes 24-48 hours to appear for all users after enabling.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-externalinoutlook'
}
