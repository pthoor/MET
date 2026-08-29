$referenceUrl = 'https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/authenticated-client-smtp-submission'

$recommendation = 'Microsoft''s guidance is to disable SMTP AUTH tenant-wide and re-enable it only on the specific mailboxes that still need it. Run: Set-TransportConfig -SmtpClientAuthenticationDisabled $true, then, for each mailbox that genuinely requires client submission, Set-CASMailbox -Identity <mailbox> -SmtpClientAuthenticationDisabled $false. Inventory the appliances and applications still submitting mail this way (multifunction printers, scanners, monitoring and line-of-business apps) before turning it off - mail from anything left behind will start failing to submit. Separately, block Basic authentication for the protocol with an authentication policy (Set-AuthenticationPolicy -AllowBasicAuthSmtp $false): SMTP AUTH also supports OAuth, so blocking Basic leaves OAuth-capable clients working while closing the password-only path. Where the device supports neither, move it to a dedicated authenticated relay connector scoped to its source IP.'

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
        -Finding 'SMTP AUTH client submission is enabled tenant-wide (SmtpClientAuthenticationDisabled is not set to true), so every mailbox in the organisation can submit mail over the protocol rather than only the mailboxes that need it. SMTP AUTH accepts OAuth as well as Basic authentication, so this alone does not prove a password-only endpoint is exposed - but unless an authentication policy separately blocks Basic for SMTP, the protocol will accept a username and password directly, with no multi-factor prompt and exempt from most Conditional Access policies. That path is reachable from anywhere on the internet and is continuously scanned for password spray and credential stuffing.' `
        -Recommendation $recommendation `
        -ReferenceUrl $referenceUrl
    return
}

try {
    $casMailboxes = @(Get-EXOCasMailbox -ResultSize Unlimited -Properties SmtpClientAuthenticationDisabled -ErrorAction Stop)
}
catch {
    New-METCheckResult -CheckId 'MET-EXO019' -Category EXO -Name 'SMTP Client Authentication' `
        -Result Warning -Severity High -AffectedObject 'Transport Configuration' `
        -Finding 'SMTP AUTH client submission is disabled tenant-wide. Per-mailbox overrides could not be enumerated, so any number of mailboxes may still have SMTP AUTH explicitly re-enabled and the exposure this check exists to find is unverified - re-run with an account that can read mailbox CAS settings to confirm.' `
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
        -Finding "SMTP AUTH client submission is disabled tenant-wide, but $($overrides.Count) mailbox(es) explicitly re-enable it and are therefore exempt from that baseline: $sampleText$suffix. Unless an authentication policy separately blocks Basic authentication for SMTP, each of these is a live password-only endpoint that bypasses most Conditional Access and can be password-sprayed." `
        -Recommendation $recommendation `
        -ReferenceUrl $referenceUrl
}
else {
    New-METCheckResult -CheckId 'MET-EXO019' -Category EXO -Name 'SMTP Client Authentication' `
        -Result Pass -Severity High -AffectedObject 'Transport Configuration' `
        -Finding 'SMTP AUTH client submission is disabled tenant-wide and no mailbox explicitly re-enables it' `
        -ReferenceUrl $referenceUrl
}
