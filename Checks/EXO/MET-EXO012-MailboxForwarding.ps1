try {
    $mailboxes = Get-EXOMailbox -ResultSize Unlimited -Properties ForwardingSmtpAddress,ForwardingAddress,DeliverToMailboxAndForward,PrimarySmtpAddress -Filter "ForwardingSmtpAddress -ne `$null -or ForwardingAddress -ne `$null" -ErrorAction Stop
}
catch {
    New-METCheckResult -CheckId 'MET-EXO012' -Category EXO -Name 'Mailbox Forwarding' `
        -Result Fail -Severity Critical -AffectedObject 'Mailboxes' `
        -Finding 'Unable to retrieve mailboxes with forwarding configured' `
        -Recommendation 'Ensure the account has Exchange View-Only Recipients permission.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-exomailbox' `
        -ErrorMessage $_.ToString()
    return
}

$mailboxes = @($mailboxes | Where-Object { $_.ForwardingSmtpAddress -or $_.ForwardingAddress })

if ($mailboxes.Count -eq 0) {
    New-METCheckResult -CheckId 'MET-EXO012' -Category EXO -Name 'Mailbox Forwarding' `
        -Result Info -Severity Critical -AffectedObject 'Mailboxes' `
        -Finding 'No mailboxes found with forwarding configured' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-exomailbox'
    return
}

$totalCount  = $mailboxes.Count
$silentCount = @($mailboxes | Where-Object { $_.DeliverToMailboxAndForward -eq $false }).Count

$sampleLines = [System.Collections.Generic.List[string]]::new()
$sampleCap   = 10
$index       = 0

foreach ($mbx in $mailboxes) {
    if ($index -ge $sampleCap) {
        break
    }

    $target = if ($mbx.ForwardingSmtpAddress) { $mbx.ForwardingSmtpAddress } else { $mbx.ForwardingAddress }
    $silentSuffix = if (-not $mbx.DeliverToMailboxAndForward) { ' [silent - no local copy retained]' } else { '' }
    $sampleLines.Add("$($mbx.PrimarySmtpAddress) -> $target$silentSuffix")
    $index++
}

if ($totalCount -gt $sampleCap) {
    $sampleLines.Add("...and $($totalCount - $sampleCap) more")
}

New-METCheckResult -CheckId 'MET-EXO012' -Category EXO -Name 'Mailbox Forwarding' `
    -Result Warning -Severity Critical `
    -AffectedObject "Mailboxes ($totalCount with forwarding)" `
    -Finding "$totalCount mailbox(es) have forwarding configured; $silentCount are silent (no local copy retained). $($sampleLines -join '; ')" `
    -Recommendation 'Review each forwarding mailbox. Attacker-configured forwarding after a credential compromise is a common way to exfiltrate mail (invoices, wire approvals, credentials) even after the password is reset - especially "silent" forwarding where DeliverToMailboxAndForward is $false, since the mailbox owner never sees a copy and has no visual cue anything is wrong. Confirm each entry is a known, intentional business need (e.g. shared mailbox routing, employee departure handoff). Remove unexpected entries immediately and treat them as a potential compromise indicator. Run: Set-Mailbox -Identity <mailbox> -ForwardingSmtpAddress $null to remove.' `
    -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-exomailbox'
