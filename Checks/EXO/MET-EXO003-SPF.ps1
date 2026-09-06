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
        New-METCheckResult -CheckId 'MET-EXO003' -Category EXO -Name 'SPF' `
            -Result Fail -Severity High -AffectedObject 'Accepted Domains' `
            -Finding 'Unable to retrieve accepted domains' `
            -Recommendation 'Ensure the account has Exchange View-Only Recipients permission.' `
            -ReferenceUrl 'https://aka.ms/spf' -ErrorMessage $_.ToString()
        return
    }
}

function Measure-SpfLookups {
    param([string] $DomainName, [int] $Depth = 0, [System.Collections.Generic.HashSet[string]] $Visited = $null)

    # RFC 7208 4.6.4 caps a valid record at 10 DNS-querying mechanisms, so a chain
    # deeper than that is already over the limit. Complete=$false here (rather than
    # just stopping) is what stops a truncated walk from being reported as a fact.
    if ($Depth -gt 10) { return [PSCustomObject]@{ Count = 0; Complete = $false } }
    if (-not $Visited) { $Visited = [System.Collections.Generic.HashSet[string]]::new() }
    if (-not $Visited.Add($DomainName)) { return [PSCustomObject]@{ Count = 0; Complete = $true } }

    $count = 0
    $complete = $true
    try {
        $txt = Resolve-METDnsName -Name $DomainName -Type TXT |
            Where-Object { $_.Strings -match '^v=spf1' } |
            Select-Object -First 1

        if (-not $txt) { return [PSCustomObject]@{ Count = 0; Complete = $true } }

        $record = $txt.Strings -join ''
        $terms = $record -split '\s+' | Where-Object { $_ }

        foreach ($term in $terms) {
            if ($term -eq 'v=spf1') {
                continue
            }

            $normalized = $term -replace '^[\+\-\~\?]', ''

            if ($normalized -match '^include:([^\s]+)$') {
                $count += 1
                $nested = Measure-SpfLookups -DomainName $Matches[1] -Depth ($Depth + 1) -Visited $Visited
                $count += $nested.Count
                $complete = $complete -and $nested.Complete
                continue
            }

            if ($normalized -match '^redirect=([^\s]+)$') {
                $count += 1
                $nested = Measure-SpfLookups -DomainName $Matches[1] -Depth ($Depth + 1) -Visited $Visited
                $count += $nested.Count
                $complete = $complete -and $nested.Complete
                continue
            }

            if ($normalized -match '^(a|mx|ptr)([:/].*)?$' -or $normalized -match '^exists:([^\s]+)$') {
                $count += 1
            }
        }
    }
    catch {
        Write-Verbose "DNS lookup failed for '$DomainName' during SPF lookup count: $_"
        $complete = $false
    }

    return [PSCustomObject]@{ Count = $count; Complete = $complete }
}

foreach ($domain in $domains) {
    $spfRecord = $null
    $lookupError = $null

    try {
        $dns = Resolve-METDnsName -Name $domain.DomainName -Type TXT
        $spfRecord = $dns | Where-Object { $_.Strings -match '^v=spf1' } | Select-Object -First 1
    }
    catch {
        $lookupError = $_
        Write-Verbose "DNS lookup failed for '$($domain.DomainName)': $_"
    }

    if ($lookupError) {
        New-METCheckResult -CheckId 'MET-EXO003' -Category EXO -Name 'SPF' `
            -Result Warning -Severity High -AffectedObject $domain.DomainName `
            -Finding 'Unable to determine SPF status because the DNS lookup failed' `
            -Recommendation 'Restore DNS connectivity or install dig/nslookup, then rerun the assessment.' `
            -ReferenceUrl 'https://aka.ms/spf' -ErrorMessage $lookupError.ToString()
        continue
    }

    if (-not $spfRecord) {
        New-METCheckResult -CheckId 'MET-EXO003' -Category EXO -Name 'SPF' `
            -Result Fail -Severity High -AffectedObject $domain.DomainName `
            -Finding 'No SPF TXT record found' `
            -Recommendation "Publish an SPF record: 'v=spf1 include:spf.protection.outlook.com -all'" `
            -ReferenceUrl 'https://aka.ms/spf'
        continue
    }

    $record = $spfRecord.Strings -join ''
    $issues = [System.Collections.Generic.List[string]]::new()
    $terms = @($record -split '\s+' | Where-Object { $_ })

    # RFC 7208 5.1: 'all' is a mechanism term, so it is only an enforcement qualifier
    # when it stands as its own term. Matching the substring '-all' against the whole
    # record reads an include or hostname such as 'a:mail-all.contoso.com' as enforcement.
    $allTerm = $terms | Where-Object { $_ -match '^[+\-~?]?all$' } | Select-Object -First 1
    $allQualifier = $null
    if ($allTerm) {
        $allQualifier = if ($allTerm -match '^([+\-~?])') { $Matches[1] } else { '+' }
    }
    $redirectTerm = $terms | Where-Object { $_ -match '^redirect=(.+)$' } | Select-Object -First 1

    # RFC 7208 2.6.2: a neutral result and an absent 'all' term both fall back to
    # the same default the receiver applies when no SPF record exists at all - the
    # spec requires treating Neutral "exactly like the None result". Those two and
    # '+all' (explicit allow-all) are therefore the same amount of protection: none.
    $allForcesFail = $false
    if ($allQualifier -eq '+') {
        $issues.Add("SPF record uses '+all' (allow all) - any server can send as this domain")
        $allForcesFail = $true
    }
    elseif ($allQualifier -eq '?') {
        $issues.Add("SPF record uses '?all' (neutral) - RFC 7208 requires receivers to treat a neutral result exactly as if no SPF record were published")
        $allForcesFail = $true
    }
    elseif ($allQualifier -eq '~') {
        $issues.Add("SPF record uses '~all' (soft fail) - consider '-all' for strict enforcement")
    }
    elseif (-not $allQualifier -and $redirectTerm) {
        $issues.Add("SPF record has no 'all' mechanism and defers to $redirectTerm - enforcement is whatever that record declares and was not evaluated here")
    }
    elseif (-not $allQualifier) {
        $issues.Add("SPF record has no 'all' mechanism - unmatched senders get the default 'neutral' result, which receivers must treat as if no SPF record were published")
        $allForcesFail = $true
    }

    $lookupResult = Measure-SpfLookups -DomainName $domain.DomainName
    $lookupCount = $lookupResult.Count
    if ($lookupCount -gt 10) {
        $issues.Add("SPF record exceeds 10 DNS lookups ($lookupCount) - may cause SPF permerror")
    }
    elseif (-not $lookupResult.Complete) {
        $issues.Add("SPF lookup count could not be completed - at least $lookupCount DNS-querying mechanisms were counted before a nested lookup failed or the include chain was truncated, so the 10-lookup limit was not verified")
    }

    if ($issues.Count -gt 0) {
        $result = if ($allForcesFail) { 'Fail' } else { 'Warning' }
        New-METCheckResult -CheckId 'MET-EXO003' -Category EXO -Name 'SPF' `
            -Result $result -Severity High -AffectedObject $domain.DomainName `
            -Finding "$($issues -join '; ') | Record: $record" `
            -Recommendation "Use '-all' to strictly reject unauthorised senders. Reduce includes to stay within the 10-lookup limit." `
            -ReferenceUrl 'https://aka.ms/spf'
    }
    else {
        New-METCheckResult -CheckId 'MET-EXO003' -Category EXO -Name 'SPF' `
            -Result Pass -Severity High -AffectedObject $domain.DomainName `
            -Finding "SPF record is present and correctly configured ($lookupCount DNS lookups) | Record: $record" `
            -ReferenceUrl 'https://aka.ms/spf'
    }
}
