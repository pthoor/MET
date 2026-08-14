try {
    $orgConfig = Get-OrganizationConfig -ErrorAction Stop
}
catch {
    New-METCheckResult -CheckId 'MET-EXO010' -Category EXO -Name 'Direct Send Protection' `
        -Result Fail -Severity Critical -AffectedObject 'Organization Configuration' `
        -Finding 'Unable to retrieve organization configuration' `
        -Recommendation 'Ensure the account has Security Reader or higher permissions.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-organizationconfig' -ErrorMessage $_.ToString()
    return
}

if ($orgConfig.RejectDirectSend -eq $true) {
    New-METCheckResult -CheckId 'MET-EXO010' -Category EXO -Name 'Direct Send Protection' `
        -Result Pass -Severity Critical -AffectedObject 'Organization Configuration' `
        -Finding 'Direct Send is blocked - unauthenticated senders cannot relay mail through this tenant''s own domain without SMTP authentication' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-organizationconfig'
}
else {
    New-METCheckResult -CheckId 'MET-EXO010' -Category EXO -Name 'Direct Send Protection' `
        -Result Fail -Severity Critical -AffectedObject 'Organization Configuration' `
        -Finding 'Direct Send is not blocked (RejectDirectSend is disabled) - unauthenticated senders can relay mail through this tenant''s own accepted domains without SMTP authentication, and attackers can abuse this identical path to spoof internal senders, bypassing anti-spoofing controls entirely since the message never authenticates as external' `
        -Recommendation 'Run: Set-OrganizationConfig -RejectDirectSend $true. This blocks unauthenticated Direct Send traffic while still allowing mail from configured connectors and authenticated senders (SMTP AUTH client submission). Before enabling broadly, identify and migrate any legitimate Direct Send senders (printers, scanners, line-of-business apps) to SMTP AUTH client submission or a dedicated connector, or their mail will start being rejected.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-organizationconfig'
}
