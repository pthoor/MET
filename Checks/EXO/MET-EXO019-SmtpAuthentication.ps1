$referenceUrl = 'https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/authenticated-client-smtp-submission'

$recommendation = 'Run: Set-TransportConfig -SmtpClientAuthenticationDisabled $true to turn off legacy SMTP AUTH client submission tenant-wide, then clear any per-mailbox exceptions with: Set-CASMailbox -Identity <mailbox> -SmtpClientAuthenticationDisabled $null so those mailboxes inherit the tenant setting. Before turning it off, inventory the appliances and applications still submitting mail with SMTP AUTH (multifunction printers, scanners, monitoring and line-of-business apps) and migrate each one first - either to a client that supports OAuth for SMTP AUTH, or to a dedicated authenticated relay connector scoped to that device''s source IP. Mail from anything left behind will start failing to submit.'

try {
    $transportConfig = Get-TransportConfig -ErrorAction Stop
}
catch {
    New-METCheckResult -CheckId 'MET-EXO019' -Category EXO -Name 'SMTP Client Authentication' `
        -Result Fail -Severity High -AffectedObject 'Transport Configuration' `
        -Finding 'Unable to retrieve transport configuration' `
        -Recommendation 'Ensure the account has Exchange View-Only Configuration or higher permissions.' `
        -ReferenceUrl $referenceUrl -ErrorMessage $_.ToString()
    return
}

if ($transportConfig.SmtpClientAuthenticationDisabled -ne $true) {
    New-METCheckResult -CheckId 'MET-EXO019' -Category EXO -Name 'SMTP Client Authentication' `
        -Result Fail -Severity High -AffectedObject 'Transport Configuration' `
        -Finding 'Legacy SMTP AUTH client submission is enabled tenant-wide (SmtpClientAuthenticationDisabled is not set to true). SMTP AUTH is a basic-authentication endpoint: it submits a username and password directly, supports no multi-factor prompt, and is exempt from most Conditional Access policy, so it is a standing target for password spray and credential stuffing. A single valid password is enough to send mail as that user from anywhere on the internet.' `
        -Recommendation $recommendation `
        -ReferenceUrl $referenceUrl
    return
}

try {
    $casMailboxes = @(Get-EXOCasMailbox -ResultSize Unlimited -Properties SmtpClientAuthenticationDisabled -ErrorAction Stop)
}
catch {
    New-METCheckResult -CheckId 'MET-EXO019' -Category EXO -Name 'SMTP Client Authentication' `
        -Result Pass -Severity High -AffectedObject 'Transport Configuration' `
        -Finding 'Legacy SMTP AUTH client submission is disabled tenant-wide. Per-mailbox overrides could not be enumerated, so individual mailboxes may still have SMTP AUTH explicitly re-enabled - re-run with an account that can read mailbox CAS settings to confirm.' `
        -Recommendation $recommendation `
        -ReferenceUrl $referenceUrl -ErrorMessage $_.ToString()
    return
}

$overrides = @(
    $casMailboxes | Where-Object {
        $null -ne $_.SmtpClientAuthenticationDisabled -and $_.SmtpClientAuthenticationDisabled -eq $false
    }
)

if ($overrides.Count -gt 0) {
    $sample = @($overrides | Select-Object -First 10 | ForEach-Object { [string]$_.PrimarySmtpAddress })
    $sampleText = $sample -join ', '
    $suffix = if ($overrides.Count -gt $sample.Count) { " (showing first $($sample.Count) of $($overrides.Count))" } else { '' }

    New-METCheckResult -CheckId 'MET-EXO019' -Category EXO -Name 'SMTP Client Authentication' `
        -Result Warning -Severity High -AffectedObject "Mailbox SMTP AUTH Overrides ($($overrides.Count) mailboxes)" `
        -Finding "Legacy SMTP AUTH client submission is disabled tenant-wide, but $($overrides.Count) mailbox(es) explicitly re-enable it and are therefore exempt from that baseline: $sampleText$suffix. Each of these is a live basic-authentication endpoint that bypasses most Conditional Access and can be password-sprayed." `
        -Recommendation $recommendation `
        -ReferenceUrl $referenceUrl
}
else {
    New-METCheckResult -CheckId 'MET-EXO019' -Category EXO -Name 'SMTP Client Authentication' `
        -Result Pass -Severity High -AffectedObject 'Transport Configuration' `
        -Finding 'Legacy SMTP AUTH client submission is disabled tenant-wide and no mailbox explicitly re-enables it' `
        -ReferenceUrl $referenceUrl
}
