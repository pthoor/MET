try {
    $config = Get-ExternalInOutlook -ErrorAction Stop
}
catch {
    New-METCheckResult -CheckId 'MET-EXO015' -Category EXO -Name 'External Sender Warning Tag' `
        -Result Fail -Severity Medium -AffectedObject 'External Sender Tag Configuration' `
        -Finding 'Unable to retrieve external sender tag configuration' `
        -Recommendation 'Ensure the account has Security Reader or higher permissions.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-externalinoutlook' -ErrorMessage $_.ToString()
    return
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
