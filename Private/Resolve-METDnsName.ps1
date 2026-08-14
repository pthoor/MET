function Resolve-METDnsName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [ValidateSet('TXT')] [string] $Type
    )

    # On Windows, delegate to the native Resolve-DnsName cmdlet (DnsClient module).
    if ($IsWindows -ne $false) {
        return Resolve-DnsName -Name $Name -Type $Type -DnsOnly -ErrorAction Stop
    }

    # Non-Windows: build compatible result objects using dig (preferred) or nslookup.
    $records = [System.Collections.Generic.List[PSCustomObject]]::new()

    if (Get-Command -Name dig -CommandType Application -ErrorAction SilentlyContinue) {
        $raw = & dig +short $Type $Name 2>&1

        foreach ($line in ($raw | Where-Object { $_ -match '\S' })) {
            $text = ($line -replace '"', '').Trim()
            if (-not $text) { continue }

            $records.Add([PSCustomObject]@{
                Name    = $Name
                Type    = $Type
                TTL     = 0
                Strings = @($text)
            })
        }
    }
    elseif (Get-Command -Name nslookup -CommandType Application -ErrorAction SilentlyContinue) {
        $raw = & nslookup "-type=$Type" $Name 2>&1

        foreach ($line in $raw) {
            # TXT records appear as: text = "v=spf1 ..."  or  "v=spf1 ..."
            if ($line -match '(?:text\s*=\s*)?"([^"]+)"') {
                $records.Add([PSCustomObject]@{
                    Name    = $Name
                    Type    = $Type
                    TTL     = 0
                    Strings = @($Matches[1].Trim())
                })
            }
        }
    }
    else {
        # Minimal Linux containers (including GitHub Codespaces) often omit both
        # bind-utils and dnsutils. Use DNS-over-HTTPS rather than treating that
        # missing local tooling as proof that a DNS record does not exist.
        $escapedName = [uri]::EscapeDataString($Name)
        $uri = "https://dns.google/resolve?name=$escapedName&type=$Type"

        try {
            $response = Invoke-RestMethod -Uri $uri -Method Get -Headers @{ Accept = 'application/dns-json' } -ErrorAction Stop
        }
        catch {
            throw "DNS lookup for '$Name' failed using the DNS-over-HTTPS fallback: $($_.Exception.Message)"
        }

        # Status 3 is an authoritative NXDOMAIN response: the lookup succeeded,
        # but the requested name does not exist. Other non-zero statuses are DNS
        # failures and must not be reported as an absent policy record.
        if ([int]$response.Status -eq 3) {
            return @()
        }
        if ([int]$response.Status -ne 0) {
            throw "DNS-over-HTTPS lookup for '$Name' returned status $($response.Status)."
        }

        foreach ($answer in @($response.Answer | Where-Object { [int]$_.type -eq 16 })) {
            # DNS JSON represents a TXT RR as one or more quoted character
            # strings. Join adjacent strings to match Resolve-DnsName's shape.
            $text = [string]$answer.data
            $text = [regex]::Replace($text, '"\s+"', '')
            $text = $text.Trim('"')
            if (-not $text) { continue }

            $records.Add([PSCustomObject]@{
                Name    = $Name
                Type    = $Type
                TTL     = [int]$answer.TTL
                Strings = @($text)
            })
        }
    }

    return $records.ToArray()
}
