[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'METCheckInfo',
    Justification = 'Check metadata. Read from the AST by Get-METCheck and never executed.')]
param()

$METCheckInfo = @{
    Name           = 'Direct Send Protection'
    Severity       = 'Critical'
    Description    = 'Checks RejectDirectSend on Get-OrganizationConfig to determine whether unauthenticated senders can relay mail through the tenant''s own domain without SMTP auth.'
    RequiresModule = @('ExchangeOnlineManagement')
}

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
        -Finding 'RejectDirectSend was not returned by Get-OrganizationConfig, so whether Direct Send is blocked was not established. This is graded a failure rather than an unassessed gap because the platform default for Direct Send is not blocked, so an absent value is a likelier sign of a real gap than of a tenant that already hardened it.' `
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
