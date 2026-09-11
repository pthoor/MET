[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'METCheckInfo',
    Justification = 'Check metadata. Read from the AST by Get-METCheck and never executed.')]
param()

$METCheckInfo = @{
    Name           = 'Mailbox Forwarding'
    Severity       = 'High'
    Description    = 'Checks ForwardingSmtpAddress, ForwardingAddress, and DeliverToMailboxAndForward on every mailbox, flagging silent forwarding with no local copy.'
    RequiresModule = @('ExchangeOnlineManagement')
}

$referenceUrl = 'https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-exomailbox'

try {
    $mailboxes = Get-EXOMailbox -ResultSize Unlimited -Properties ForwardingSmtpAddress,ForwardingAddress,DeliverToMailboxAndForward,PrimarySmtpAddress -Filter "ForwardingSmtpAddress -ne `$null -or ForwardingAddress -ne `$null" -ErrorAction Stop
}
catch {
    New-METCheckResult -CheckId 'MET-EXO012' -Category EXO -Name 'Mailbox Forwarding' `
        -Result Fail -Severity High -AffectedObject 'Mailboxes' `
        -Finding 'Unable to retrieve mailboxes with forwarding configured' `
        -Recommendation 'Ensure the account has Exchange View-Only Recipients permission.' `
        -ReferenceUrl $referenceUrl `
        -ErrorMessage $_.ToString()
    return
}

$mailboxes = @($mailboxes | Where-Object { $_.ForwardingSmtpAddress -or $_.ForwardingAddress })

if ($mailboxes.Count -eq 0) {
    New-METCheckResult -CheckId 'MET-EXO012' -Category EXO -Name 'Mailbox Forwarding' `
        -Result Pass -Severity High -AffectedObject 'Mailboxes' `
        -Finding 'No mailboxes have a forwarding address configured, so no mail is being automatically forwarded out of the tenant by mailbox-level forwarding' `
        -ReferenceUrl $referenceUrl
    return
}

$totalCount = $mailboxes.Count
$silent = [System.Collections.Generic.List[string]]::new()
$unconfirmed = [System.Collections.Generic.List[string]]::new()

foreach ($mbx in $mailboxes) {
    $address = [string]$mbx.PrimarySmtpAddress
    if ($null -eq $mbx.PSObject.Properties['DeliverToMailboxAndForward'] -or $null -eq $mbx.DeliverToMailboxAndForward) {
        $unconfirmed.Add($address)
    }
    elseif ($mbx.DeliverToMailboxAndForward -eq $false) {
        $silent.Add($address)
    }
}

$sampleLines = [System.Collections.Generic.List[string]]::new()
$sampleCap = 10
$index = 0

foreach ($mbx in $mailboxes) {
    if ($index -ge $sampleCap) {
        break
    }

    $target = if ($mbx.ForwardingSmtpAddress) { $mbx.ForwardingSmtpAddress } else { $mbx.ForwardingAddress }
    $address = [string]$mbx.PrimarySmtpAddress
    $suffix = if ($unconfirmed.Contains($address)) {
        ' [DeliverToMailboxAndForward not returned - local copy retention unconfirmed]'
    }
    elseif ($silent.Contains($address)) {
        ' [silent - no local copy retained]'
    }
    else {
        ''
    }

    $sampleLines.Add("$address -> $target$suffix")
    $index++
}

if ($totalCount -gt $sampleCap) {
    $sampleLines.Add("...and $($totalCount - $sampleCap) more")
}

$sampleText = $sampleLines -join '; '
$unconfirmedSample = @($unconfirmed | Select-Object -First $sampleCap) -join ', '
$unconfirmedSuffix = if ($unconfirmed.Count -gt $sampleCap) { " (and $($unconfirmed.Count - $sampleCap) more)" } else { '' }
$removalGuidance = 'Confirm each entry is a known, intentional business need (e.g. shared mailbox routing, employee departure handoff). Remove unexpected entries immediately and treat them as a potential compromise indicator. Run: Set-Mailbox -Identity <mailbox> -ForwardingSmtpAddress $null to remove.'

if ($silent.Count -gt 0) {
    $unconfirmedText = if ($unconfirmed.Count -gt 0) { " DeliverToMailboxAndForward was not returned for a further $($unconfirmed.Count) mailbox(es) ($unconfirmedSample$unconfirmedSuffix), so whether those retain a local copy was not established." } else { '' }

    New-METCheckResult -CheckId 'MET-EXO012' -Category EXO -Name 'Mailbox Forwarding' `
        -Result Warning -Severity High `
        -AffectedObject "Mailboxes ($totalCount with forwarding)" `
        -Finding "$($silent.Count) of $totalCount mailbox(es) with forwarding configured forward silently - DeliverToMailboxAndForward is `$false, so no local copy is retained and the mailbox owner never sees the forwarded mail.$unconfirmedText $sampleText" `
        -Recommendation "Review each forwarding mailbox, starting with the silent ones. Attacker-configured forwarding after a credential compromise is a common way to exfiltrate mail (invoices, wire approvals, credentials) even after the password is reset - especially silent forwarding, since the mailbox owner never sees a copy and has no visual cue anything is wrong. $removalGuidance" `
        -ReferenceUrl $referenceUrl
    return
}

if ($unconfirmed.Count -gt 0) {
    New-METCheckResult -CheckId 'MET-EXO012' -Category EXO -Name 'Mailbox Forwarding' `
        -Result Warning -Severity High `
        -AffectedObject "Mailboxes ($totalCount with forwarding)" `
        -Finding "$totalCount mailbox(es) have forwarding configured, and DeliverToMailboxAndForward was not returned for $($unconfirmed.Count) of them ($unconfirmedSample$unconfirmedSuffix), so whether a local copy is retained was not established for those. An unconfirmed state is reported as a gap rather than a clean result, because nothing here distinguishes a mailbox that retains a local copy from one forwarding silently. $sampleText" `
        -Recommendation "Confirm the state directly: Get-EXOMailbox -Identity <mailbox> -Properties DeliverToMailboxAndForward | Format-List PrimarySmtpAddress, ForwardingSmtpAddress, DeliverToMailboxAndForward. Forwarding with no local copy retained is the higher-risk pattern, since the mailbox owner never sees a copy and has no visual cue anything is wrong. $removalGuidance" `
        -ReferenceUrl $referenceUrl
    return
}

New-METCheckResult -CheckId 'MET-EXO012' -Category EXO -Name 'Mailbox Forwarding' `
    -Result Info -Severity High `
    -AffectedObject "Mailboxes ($totalCount with forwarding)" `
    -Finding "$totalCount mailbox(es) have forwarding configured and every one retains a local copy (DeliverToMailboxAndForward is `$true), so none of them forwards silently. They are listed here for review rather than as a gap. $sampleText" `
    -Recommendation "Forwarding that retains a local copy is often a legitimate configuration (shared mailbox routing, employee departure handoff), so this is a review item rather than a finding. $removalGuidance" `
    -ReferenceUrl $referenceUrl
