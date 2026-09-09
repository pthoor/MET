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

$rejectDirectSendProperty = $orgConfig.PSObject.Properties['RejectDirectSend']
if (-not $rejectDirectSendProperty -or $null -eq $rejectDirectSendProperty.Value) {
    New-METCheckResult -CheckId 'MET-EXO010' -Category EXO -Name 'Direct Send Protection' `
        -Result Fail -Severity Critical -AffectedObject 'Organization Configuration' `
        -Finding 'RejectDirectSend was not returned by Get-OrganizationConfig, so whether Direct Send is blocked was not established. RejectDirectSend is a relatively recent property - an absent value usually means an ExchangeOnlineManagement version that does not expose it yet, not a hypothetical.' `
        -Recommendation 'Update ExchangeOnlineManagement to a version that returns RejectDirectSend and rerun the assessment, or confirm directly with: Get-OrganizationConfig | Format-List RejectDirectSend. If it is genuinely unset, run: Set-OrganizationConfig -RejectDirectSend $true. This blocks unauthenticated Direct Send traffic while still allowing mail from configured connectors and authenticated senders (SMTP AUTH client submission). Before enabling broadly, identify and migrate any legitimate Direct Send senders (printers, scanners, line-of-business apps) to SMTP AUTH client submission or a dedicated connector, or their mail will start being rejected.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-organizationconfig' `
        -ErrorMessage 'Get-OrganizationConfig did not return a RejectDirectSend value.'
}
elseif ($rejectDirectSendProperty.Value -eq $true) {
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
