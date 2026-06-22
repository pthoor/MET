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
        throw "No DNS tool available on this platform. Install 'dig' or 'nslookup' to run DMARC and SPF checks."
    }

    return $records.ToArray()
}
