# Use pre-fetched accepted domains from context when available; fall back to a live query.
$domains = $null
if ($METContext -and $METContext.AcceptedDomains.Count -gt 0) {
    $domains = @($METContext.AcceptedDomains | Where-Object { $_.Default -or $_.DomainType -eq 'Authoritative' })
}

if (-not $domains) {
    try {
        $domains = @(Get-AcceptedDomain -ErrorAction Stop | Where-Object { $_.Default -or $_.DomainType -eq 'Authoritative' })
    }
    catch {
        New-METCheckResult -CheckId 'MET-EXO001' -Category EXO -Name 'DMARC' `
            -Result Fail -Severity High -AffectedObject 'Accepted Domains' `
            -Finding 'Unable to retrieve accepted domains' `
            -Recommendation 'Ensure the account has Exchange View-Only Recipients permission.' `
            -ReferenceUrl 'https://aka.ms/dmarc' -ErrorMessage $_.ToString()
        return
    }
}

function Get-METDmarcRecommendation {
    param(
        [Parameter(Mandatory)] [string] $DomainName,
        [Parameter(Mandatory)] [bool] $IsOnMicrosoftDomain
    )

    if ($IsOnMicrosoftDomain) {
        return "Add a DMARC TXT record for $DomainName in Microsoft 365 admin center (Settings > Domains > $DomainName > DNS records). Recommended value: 'v=DMARC1; p=reject; rua=mailto:dmarc-reports@$DomainName'."
    }

    return "Publish a DMARC TXT record at _dmarc.$DomainName with at minimum 'v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@$DomainName'."
}

foreach ($domain in $domains) {
    $domainName = [string]$domain.DomainName
    $isMailOnMicrosoft = $domainName -match '(?i)\.mail\.onmicrosoft\.com$'
    $isOnMicrosoftDomain = $domainName -match '(?i)\.onmicrosoft\.com$'

    if ($isMailOnMicrosoft) {
        New-METCheckResult -CheckId 'MET-EXO001' -Category EXO -Name 'DMARC' `
            -Result NotApplicable -Severity Informational -AffectedObject $domainName `
            -Finding 'mail.onmicrosoft.com service domain is Microsoft-managed and not intended for customer DMARC DNS management.' `
            -Recommendation 'No action needed unless Microsoft guidance for this service domain changes.' `
            -ReferenceUrl 'https://aka.ms/dmarc'
        continue
    }

    $dmarcRecord = $null
    try {
        $dns = Resolve-METDnsName -Name "_dmarc.$domainName" -Type TXT
        $dmarcRecord = $dns | Where-Object { $_.Strings -match '^v=DMARC1' } | Select-Object -First 1
    }
    catch {
        New-METCheckResult -CheckId 'MET-EXO001' -Category EXO -Name 'DMARC' `
            -Result Fail -Severity High -AffectedObject $domainName `
            -Finding 'No DMARC record found (DNS lookup failed or record absent)' `
            -Recommendation (Get-METDmarcRecommendation -DomainName $domainName -IsOnMicrosoftDomain $isOnMicrosoftDomain) `
            -ReferenceUrl 'https://aka.ms/dmarc'
        continue
    }

    if (-not $dmarcRecord) {
        New-METCheckResult -CheckId 'MET-EXO001' -Category EXO -Name 'DMARC' `
            -Result Fail -Severity High -AffectedObject $domainName `
            -Finding 'No DMARC TXT record found' `
            -Recommendation (Get-METDmarcRecommendation -DomainName $domainName -IsOnMicrosoftDomain $isOnMicrosoftDomain) `
            -ReferenceUrl 'https://aka.ms/dmarc'
        continue
    }

    $record = ($dmarcRecord.Strings -join '') -join ''
    $issues = [System.Collections.Generic.List[string]]::new()

    if ($record -match 'p=none') {
        $issues.Add("DMARC policy is 'none' — no enforcement; emails failing DMARC are not quarantined or rejected")
    }
    elseif ($record -notmatch 'p=(quarantine|reject)') {
        $issues.Add('DMARC policy is not set to quarantine or reject')
    }

    if ($record -notmatch 'rua=') {
        $issues.Add('No aggregate reporting address (rua=) configured — DMARC reports will not be received')
    }

    if ($issues.Count -gt 0) {
        New-METCheckResult -CheckId 'MET-EXO001' -Category EXO -Name 'DMARC' `
            -Result Fail -Severity High -AffectedObject $domainName `
            -Finding "$($issues -join '; ') | Record: $record" `
            -Recommendation "Update DMARC policy to 'quarantine' or 'reject' and add an rua= reporting address." `
            -ReferenceUrl 'https://aka.ms/dmarc'
    }
    else {
        New-METCheckResult -CheckId 'MET-EXO001' -Category EXO -Name 'DMARC' `
            -Result Pass -Severity High -AffectedObject $domainName `
            -Finding "DMARC record present with enforcement policy and reporting configured | Record: $record" `
            -ReferenceUrl 'https://aka.ms/dmarc'
    }
}
