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

    if ($Depth -gt 5) { return 0 }
    if (-not $Visited) { $Visited = [System.Collections.Generic.HashSet[string]]::new() }
    if (-not $Visited.Add($DomainName)) { return 0 }

    $count = 0
    try {
        $txt = Resolve-METDnsName -Name $DomainName -Type TXT |
            Where-Object { $_.Strings -match '^v=spf1' } |
            Select-Object -First 1

        if (-not $txt) { return 0 }

        $record = $txt.Strings -join ''
        $terms = $record -split '\s+' | Where-Object { $_ }

        foreach ($term in $terms) {
            if ($term -eq 'v=spf1') {
                continue
            }

            $normalized = $term -replace '^[\+\-\~\?]', ''

            if ($normalized -match '^include:([^\s]+)$') {
                $count += 1
                $count += Measure-SpfLookups -DomainName $Matches[1] -Depth ($Depth + 1) -Visited $Visited
                continue
            }

            if ($normalized -match '^redirect=([^\s]+)$') {
                $count += 1
                $count += Measure-SpfLookups -DomainName $Matches[1] -Depth ($Depth + 1) -Visited $Visited
                continue
            }

            if ($normalized -match '^(a|mx|ptr)([:/].*)?$' -or $normalized -match '^exists:([^\s]+)$') {
                $count += 1
            }
        }
    }
    catch { Write-Verbose "DNS lookup failed for '$DomainName' during SPF lookup count: $_" }

    return $count
}

foreach ($domain in $domains) {
    $spfRecord = $null

    try {
        $dns = Resolve-METDnsName -Name $domain.DomainName -Type TXT
        $spfRecord = $dns | Where-Object { $_.Strings -match '^v=spf1' } | Select-Object -First 1
    }
    catch { Write-Verbose "DNS lookup failed for '$($domain.DomainName)': $_" }

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

    if ($record -match '\+all') {
        $issues.Add("SPF record uses '+all' (allow all) — any server can send as this domain")
    }
    elseif ($record -notmatch '-all' -and $record -notmatch '~all') {
        $issues.Add("SPF record does not end with '-all' or '~all' — enforcement is missing")
    }
    elseif ($record -match '~all') {
        $issues.Add("SPF record uses '~all' (soft fail) — consider '-all' for strict enforcement")
    }

    $lookupCount = Measure-SpfLookups -DomainName $domain.DomainName
    if ($lookupCount -gt 10) {
        $issues.Add("SPF record exceeds 10 DNS lookups ($lookupCount) — may cause SPF permerror")
    }

    if ($issues.Count -gt 0) {
        $result = if ($record -match '\+all') { 'Fail' } else { 'Warning' }
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
