$referenceUrl = 'https://learn.microsoft.com/en-us/exchange/mail-flow-best-practices/remote-domains/remote-domains'

try {
    $remoteDomains = @(Get-RemoteDomain -ErrorAction Stop)
}
catch {
    New-METCheckResult -CheckId 'MET-EXO018' -Category EXO -Name 'Remote Domain Automatic Forwarding' `
        -Result Fail -Severity High -AffectedObject 'Remote Domains' `
        -Finding 'Unable to retrieve remote domain configuration' `
        -Recommendation 'Ensure the account has Exchange View-Only Configuration or higher permissions.' `
        -ReferenceUrl $referenceUrl -ErrorMessage $_.ToString()
    return
}

if ($remoteDomains.Count -eq 0) {
    New-METCheckResult -CheckId 'MET-EXO018' -Category EXO -Name 'Remote Domain Automatic Forwarding' `
        -Result Info -Severity High -AffectedObject 'Remote Domains' `
        -Finding 'No remote domains are configured in this tenant, so automatic forwarding behaviour cannot be assessed from this control plane' `
        -ReferenceUrl $referenceUrl
    return
}

foreach ($remoteDomain in $remoteDomains) {
    $domainName = [string]$remoteDomain.DomainName
    $identity = [string]$remoteDomain.Name
    if ([string]::IsNullOrWhiteSpace($identity)) {
        $identity = $domainName
    }

    $affectedObject = "Remote Domain '$identity' ($domainName)"
    $isDefaultDomain = $domainName -eq '*'

    $hasProperty = $null -ne $remoteDomain.PSObject.Properties['AutoForwardEnabled'] -and $null -ne $remoteDomain.AutoForwardEnabled

    $recommendation = "Run: Set-RemoteDomain -Identity '$identity' -AutoForwardEnabled `$false. This is only one of three independent control planes for automatic forwarding, and all three must be closed: the remote domain setting assessed here, the outbound spam filter policy's AutoForwardingMode (assessed by MET-MDO007), and per-mailbox forwarding addresses (assessed by MET-EXO012). Closing one while leaving the others open still allows mail to leave the tenant automatically. Before disabling, confirm no business process depends on forwarding to this domain - disabling it breaks legitimate automatic forwarding to that domain, and affected users are not notified."

    if (-not $hasProperty) {
        New-METCheckResult -CheckId 'MET-EXO018' -Category EXO -Name 'Remote Domain Automatic Forwarding' `
            -Result Pass -Severity High -AffectedObject $affectedObject `
            -Finding 'The AutoForwardEnabled property was absent or null on this remote domain, so automatic forwarding was not asserted as enabled and is treated as not permitted - verify directly with Get-RemoteDomain if this domain matters to you' `
            -ReferenceUrl $referenceUrl
        continue
    }

    if ($remoteDomain.AutoForwardEnabled -eq $true) {
        if ($isDefaultDomain) {
            New-METCheckResult -CheckId 'MET-EXO018' -Category EXO -Name 'Remote Domain Automatic Forwarding' `
                -Result Fail -Severity High -AffectedObject $affectedObject `
                -Finding 'Automatic forwarding is enabled on the tenant-wide default remote domain (DomainName ''*''), so mail can be automatically forwarded from any mailbox to every external domain - by inbox rule or by a forwarding SMTP address. This is the standard business email compromise exfiltration path: an attacker who compromises a mailbox creates a forwarding rule and silently receives a copy of all subsequent mail, long after the password is reset.' `
                -Recommendation $recommendation `
                -ReferenceUrl $referenceUrl
        }
        else {
            New-METCheckResult -CheckId 'MET-EXO018' -Category EXO -Name 'Remote Domain Automatic Forwarding' `
                -Result Warning -Severity High -AffectedObject $affectedObject `
                -Finding "Automatic forwarding is enabled for the specific remote domain '$domainName'. This is a scoped exception rather than tenant-wide exposure, but mail can still leave the tenant automatically to that destination and the exception needs periodic review to confirm it is still required and still points at a domain you control or trust." `
                -Recommendation $recommendation `
                -ReferenceUrl $referenceUrl
        }
    }
    else {
        New-METCheckResult -CheckId 'MET-EXO018' -Category EXO -Name 'Remote Domain Automatic Forwarding' `
            -Result Pass -Severity High -AffectedObject $affectedObject `
            -Finding 'Automatic forwarding is disabled for this remote domain' `
            -ReferenceUrl $referenceUrl
    }
}
