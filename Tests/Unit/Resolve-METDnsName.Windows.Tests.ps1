BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/Resolve-METDnsName.ps1"
}

# Kept apart from Resolve-METDnsName.Tests.ps1, which asserts the non-Windows fallback
# tiers and is excluded from the Windows CI job - these cases need that job to run.
Describe 'Resolve-METDnsName on Windows' -Skip:(-not $IsWindows) {
    # Resolve-DnsName throws for answers dig and the DoH tier report as "no records".
    # Treating those throws as lookup failures graded a domain with no DMARC record as
    # "unable to determine" (Warning) on Windows, instead of the Fail it gets elsewhere.
    BeforeAll {
        function New-DnsErrorRecord([int] $Code, [string] $Id, [string] $Message) {
            [System.Management.Automation.ErrorRecord]::new(
                [System.ComponentModel.Win32Exception]::new($Code, $Message),
                "$Id,Microsoft.DnsClient.Commands.ResolveDnsName",
                [System.Management.Automation.ErrorCategory]::ResourceUnavailable,
                $null)
        }
    }

    It 'returns no records for an authoritative NXDOMAIN (DNS_ERROR_RCODE_NAME_ERROR)' {
        Mock Resolve-DnsName { throw (New-DnsErrorRecord 9003 'DNS_ERROR_RCODE_NAME_ERROR' 'DNS name does not exist') }

        @(Resolve-METDnsName -Name '_dmarc.contoso.com' -Type TXT) | Should -HaveCount 0
    }

    It 'returns no records when the name exists but has no records of the type (DNS_INFO_NO_RECORDS)' {
        Mock Resolve-DnsName { throw (New-DnsErrorRecord 9501 'DNS_INFO_NO_RECORDS' 'No records found for given DNS query') }

        @(Resolve-METDnsName -Name '_dmarc.contoso.com' -Type TXT) | Should -HaveCount 0
    }

    It 'still throws for a genuine lookup failure such as SERVFAIL' {
        Mock Resolve-DnsName { throw (New-DnsErrorRecord 9002 'DNS_ERROR_RCODE_SERVER_FAILURE' 'DNS server failure') }

        { Resolve-METDnsName -Name '_dmarc.contoso.com' -Type TXT } | Should -Throw '*DNS server failure*'
    }
}
