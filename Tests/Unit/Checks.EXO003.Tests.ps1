BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"

    # Every DNS name this check resolves - the domain itself and every include/redirect
    # target reached while counting lookups - goes through Resolve-METDnsName, which is
    # stubbed here and mocked per-Context. No test in this file touches a resolver.
    function Get-AcceptedDomain  { [CmdletBinding()] param() }
    function Resolve-METDnsName  { [CmdletBinding()] param([string]$Name,[string]$Type) }
}

Describe 'MET-EXO003 SPF' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'EXO' 'MET-EXO003-SPF.ps1'
    }

    Context 'SPF lookup counting includes bare mechanisms and redirect' {
        BeforeAll {
            Mock Get-AcceptedDomain {
                [PSCustomObject]@{ DomainName = 'contoso.com'; Default = $true; DomainType = 'Authoritative' }
            }

            Mock Resolve-METDnsName {
                param([string]$Name, [string]$Type)

                switch ($Name) {
                    'contoso.com' {
                        return [PSCustomObject]@{
                            Strings = @('v=spf1 a mx include:_spf1.contoso.com include:_spf2.contoso.com include:_spf3.contoso.com include:_spf4.contoso.com include:_spf5.contoso.com redirect=_spf6.contoso.com -all')
                        }
                    }
                    { $_ -match '^_spf[1-6]\.contoso\.com$' } {
                        return [PSCustomObject]@{ Strings = @('v=spf1 a mx -all') }
                    }
                    default {
                        return @()
                    }
                }
            }
        }

        It 'Returns Warning for more than 10 lookups' {
            $results = & $checkFile
            $result = $results | Select-Object -First 1
            $result.Result | Should -Be 'Warning'
            $result.Severity | Should -Be 'High'
            $result.Finding | Should -Match 'exceeds 10 DNS lookups'
        }
    }

    Context 'A nested include lookup throws partway through counting' {
        BeforeAll {
            Mock Get-AcceptedDomain {
                [PSCustomObject]@{ DomainName = 'contoso.com'; Default = $true; DomainType = 'Authoritative' }
            }

            Mock Resolve-METDnsName {
                param([string]$Name, [string]$Type)

                switch ($Name) {
                    'contoso.com' {
                        return [PSCustomObject]@{ Strings = @('v=spf1 include:fail.contoso.com -all') }
                    }
                    'fail.contoso.com' {
                        throw 'DNS timeout'
                    }
                    default {
                        return @()
                    }
                }
            }
        }

        It 'Returns Warning naming the count as incomplete instead of Passing on a truncated lower bound' {
            $results = & $checkFile
            $result = $results | Select-Object -First 1
            $result.Result | Should -Not -Be 'Pass'
            $result.Result | Should -Be 'Warning'
            $result.Severity | Should -Be 'High'
            $result.Finding | Should -Match 'could not be completed'
            $result.Finding | Should -Match 'at least 1 DNS-querying mechanisms'
        }
    }

    Context 'An include chain runs 11 domains deep' {
        BeforeAll {
            Mock Get-AcceptedDomain {
                [PSCustomObject]@{ DomainName = 'contoso.com'; Default = $true; DomainType = 'Authoritative' }
            }

            Mock Resolve-METDnsName {
                param([string]$Name, [string]$Type)

                switch ($Name) {
                    'contoso.com' { return [PSCustomObject]@{ Strings = @('v=spf1 include:d1.contoso.com -all') } }
                    'd1.contoso.com' { return [PSCustomObject]@{ Strings = @('v=spf1 include:d2.contoso.com') } }
                    'd2.contoso.com' { return [PSCustomObject]@{ Strings = @('v=spf1 include:d3.contoso.com') } }
                    'd3.contoso.com' { return [PSCustomObject]@{ Strings = @('v=spf1 include:d4.contoso.com') } }
                    'd4.contoso.com' { return [PSCustomObject]@{ Strings = @('v=spf1 include:d5.contoso.com') } }
                    'd5.contoso.com' { return [PSCustomObject]@{ Strings = @('v=spf1 include:d6.contoso.com') } }
                    'd6.contoso.com' { return [PSCustomObject]@{ Strings = @('v=spf1 include:d7.contoso.com') } }
                    'd7.contoso.com' { return [PSCustomObject]@{ Strings = @('v=spf1 include:d8.contoso.com') } }
                    'd8.contoso.com' { return [PSCustomObject]@{ Strings = @('v=spf1 include:d9.contoso.com') } }
                    'd9.contoso.com' { return [PSCustomObject]@{ Strings = @('v=spf1 include:d10.contoso.com') } }
                    'd10.contoso.com' { return [PSCustomObject]@{ Strings = @('v=spf1 include:d11.contoso.com') } }
                    default { return @() }
                }
            }
        }

        It 'Does not truncate an 11-deep chain into a false Pass' {
            $results = & $checkFile
            $result = $results | Select-Object -First 1
            $result.Result | Should -Not -Be 'Pass'
            $result.Result | Should -Be 'Warning'
            $result.Finding | Should -Match 'exceeds 10 DNS lookups \(11\)'
        }
    }

    Context 'DNS lookup fails' {
        BeforeAll {
            Mock Get-AcceptedDomain {
                [PSCustomObject]@{ DomainName = 'contoso.com'; Default = $true; DomainType = 'Authoritative' }
            }
            Mock Resolve-METDnsName { throw 'resolver unavailable' }
        }

        It 'Returns Warning with the lookup error instead of a false Fail' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Severity | Should -Be 'High'
            $results[0].Finding | Should -Match 'DNS lookup failed'
            $results[0].Error | Should -Match 'resolver unavailable'
        }
    }

    Context 'No SPF TXT record is published' {
        BeforeAll {
            Mock Get-AcceptedDomain {
                [PSCustomObject]@{ DomainName = 'contoso.com'; Default = $true; DomainType = 'Authoritative' }
            }
            Mock Resolve-METDnsName {
                [PSCustomObject]@{ Strings = @('MS=ms12345678') }
            }
        }

        It 'Returns Fail naming the absent record rather than matching an unrelated TXT record' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'High'
            $results[0].AffectedObject | Should -Be 'contoso.com'
            $results[0].Finding | Should -Be 'No SPF TXT record found'
            $results[0].Recommendation | Should -Match 'include:spf\.protection\.outlook\.com -all'
        }
    }

    Context 'SPF record ends with +all' {
        BeforeAll {
            Mock Get-AcceptedDomain {
                [PSCustomObject]@{ DomainName = 'contoso.com'; Default = $true; DomainType = 'Authoritative' }
            }
            Mock Resolve-METDnsName {
                param([string]$Name, [string]$Type)

                if ($Name -eq 'contoso.com') {
                    return [PSCustomObject]@{ Strings = @('v=spf1 include:spf.protection.outlook.com +all') }
                }
                return [PSCustomObject]@{ Strings = @('v=spf1 ip4:40.92.0.0/15 -all') }
            }
        }

        It 'Returns Fail naming the +all qualifier it found' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'High'
            $results[0].Finding | Should -Match "SPF record uses '\+all' \(allow all\)"
            $results[0].Finding | Should -Match 'Record: v=spf1 include:spf\.protection\.outlook\.com \+all'
        }

        It 'Does not additionally report a missing enforcement qualifier' {
            $results = & $checkFile
            $results[0].Finding | Should -Not -Match "no 'all' mechanism"
        }
    }

    Context 'SPF record ends with ?all' {
        BeforeAll {
            Mock Get-AcceptedDomain {
                [PSCustomObject]@{ DomainName = 'contoso.com'; Default = $true; DomainType = 'Authoritative' }
            }
            Mock Resolve-METDnsName {
                param([string]$Name, [string]$Type)

                if ($Name -eq 'contoso.com') {
                    return [PSCustomObject]@{ Strings = @('v=spf1 include:spf.protection.outlook.com ?all') }
                }
                return [PSCustomObject]@{ Strings = @('v=spf1 ip4:40.92.0.0/15 -all') }
            }
        }

        It 'Returns Fail naming the neutral qualifier, which RFC 7208 treats as no protection at all' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'High'
            $results[0].Finding | Should -Match "SPF record uses '\?all' \(neutral\)"
            $results[0].Finding | Should -Match 'Record: v=spf1 include:spf\.protection\.outlook\.com \?all'
        }
    }

    Context 'SPF record ends with ~all' {
        BeforeAll {
            Mock Get-AcceptedDomain {
                [PSCustomObject]@{ DomainName = 'contoso.com'; Default = $true; DomainType = 'Authoritative' }
            }
            Mock Resolve-METDnsName {
                param([string]$Name, [string]$Type)

                if ($Name -eq 'contoso.com') {
                    return [PSCustomObject]@{ Strings = @('v=spf1 include:spf.protection.outlook.com ~all') }
                }
                return [PSCustomObject]@{ Strings = @('v=spf1 ip4:40.92.0.0/15 -all') }
            }
        }

        It 'Returns Warning naming the soft-fail qualifier rather than a missing one' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Severity | Should -Be 'High'
            $results[0].Finding | Should -Match "SPF record uses '~all' \(soft fail\)"
            $results[0].Finding | Should -Not -Match "no 'all' mechanism"
            $results[0].Finding | Should -Match 'Record: v=spf1 include:spf\.protection\.outlook\.com ~all'
        }
    }

    Context 'SPF record ends with -all and stays within the lookup limit' {
        BeforeAll {
            Mock Get-AcceptedDomain {
                [PSCustomObject]@{ DomainName = 'contoso.com'; Default = $true; DomainType = 'Authoritative' }
            }
            Mock Resolve-METDnsName {
                param([string]$Name, [string]$Type)

                if ($Name -eq 'contoso.com') {
                    return [PSCustomObject]@{ Strings = @('v=spf1 include:spf.protection.outlook.com -all') }
                }
                return [PSCustomObject]@{ Strings = @('v=spf1 ip4:40.92.0.0/15 -all') }
            }
        }

        It 'Returns Pass reporting the record and the lookup count it measured' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
            $results[0].Severity | Should -Be 'High'
            $results[0].AffectedObject | Should -Be 'contoso.com'
            $results[0].Finding | Should -Match 'SPF record is present and correctly configured \(1 DNS lookups\)'
            $results[0].Finding | Should -Match 'Record: v=spf1 include:spf\.protection\.outlook\.com -all'
        }
    }

    Context 'SPF record whose mechanism arguments contain the letters "-all"' {
        BeforeAll {
            Mock Get-AcceptedDomain {
                [PSCustomObject]@{ DomainName = 'contoso.com'; Default = $true; DomainType = 'Authoritative' }
            }
            Mock Resolve-METDnsName {
                param([string]$Name, [string]$Type)

                if ($Name -eq 'contoso.com') {
                    return [PSCustomObject]@{ Strings = @('v=spf1 a:mail-all.contoso.com ?all') }
                }
                return @()
            }
        }

        It 'Reads the "all" mechanism as a term rather than a substring of a hostname' {
            $results = & $checkFile
            $results[0].Result | Should -Not -Be 'Pass'
            $results[0].Finding | Should -Not -Match 'correctly configured'
        }
    }

    Context 'SPF record with an include whose hostname contains "-all" and no all term of its own' {
        BeforeAll {
            Mock Get-AcceptedDomain {
                [PSCustomObject]@{ DomainName = 'contoso.com'; Default = $true; DomainType = 'Authoritative' }
            }
            Mock Resolve-METDnsName {
                param([string]$Name, [string]$Type)

                if ($Name -eq 'contoso.com') {
                    return [PSCustomObject]@{ Strings = @('v=spf1 include:spf-all.contoso.com') }
                }
                return [PSCustomObject]@{ Strings = @('v=spf1 ip4:203.0.113.0/24 -all') }
            }
        }

        It 'Does not treat an include target name as this domain enforcement qualifier' {
            $results = & $checkFile
            $results[0].Result | Should -Not -Be 'Pass'
            $results[0].Finding | Should -Not -Match 'correctly configured'
        }
    }

    Context 'SPF record has no all mechanism and no redirect' {
        BeforeAll {
            Mock Get-AcceptedDomain {
                [PSCustomObject]@{ DomainName = 'contoso.com'; Default = $true; DomainType = 'Authoritative' }
            }
            Mock Resolve-METDnsName {
                param([string]$Name, [string]$Type)

                if ($Name -eq 'contoso.com') {
                    return [PSCustomObject]@{ Strings = @('v=spf1 include:spf.protection.outlook.com') }
                }
                return [PSCustomObject]@{ Strings = @('v=spf1 ip4:203.0.113.0/24 -all') }
            }
        }

        It 'Returns Fail rather than Warning, matching the protection an absent record gives' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'High'
            $results[0].Finding | Should -Match "no 'all' mechanism - unmatched senders"
        }
    }

    Context 'SPF record has no all mechanism but defers to a redirect' {
        BeforeAll {
            Mock Get-AcceptedDomain {
                [PSCustomObject]@{ DomainName = 'contoso.com'; Default = $true; DomainType = 'Authoritative' }
            }
            Mock Resolve-METDnsName {
                param([string]$Name, [string]$Type)

                if ($Name -eq 'contoso.com') {
                    return [PSCustomObject]@{ Strings = @('v=spf1 redirect=_spf.fabrikam.com') }
                }
                return [PSCustomObject]@{ Strings = @('v=spf1 ip4:203.0.113.0/24 -all') }
            }
        }

        It 'Returns Warning naming the record it did not evaluate rather than claiming no enforcement' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'defers to redirect=_spf\.fabrikam\.com'
            $results[0].Finding | Should -Match 'was not evaluated here'
            $results[0].Finding | Should -Not -Match "no 'all' mechanism - unmatched senders"
        }
    }

    Context 'Several accepted domains with different SPF postures' {
        BeforeAll {
            Mock Get-AcceptedDomain {
                @(
                    [PSCustomObject]@{ DomainName = 'contoso.com'; Default = $true; DomainType = 'Authoritative' }
                    [PSCustomObject]@{ DomainName = 'fabrikam.com'; Default = $false; DomainType = 'Authoritative' }
                )
            }
            Mock Resolve-METDnsName {
                param([string]$Name, [string]$Type)

                switch ($Name) {
                    'contoso.com'  { return [PSCustomObject]@{ Strings = @('v=spf1 -all') } }
                    'fabrikam.com' { return [PSCustomObject]@{ Strings = @('v=spf1 +all') } }
                    default        { return @() }
                }
            }
        }

        It 'Reports one result per domain, each naming its own qualifier' {
            $results = & $checkFile
            $results.Count | Should -Be 2

            $contoso = $results | Where-Object { $_.AffectedObject -eq 'contoso.com' }
            $contoso.Result | Should -Be 'Pass'
            $contoso.Finding | Should -Match '\(0 DNS lookups\)'

            $fabrikam = $results | Where-Object { $_.AffectedObject -eq 'fabrikam.com' }
            $fabrikam.Result | Should -Be 'Fail'
            $fabrikam.Finding | Should -Match "SPF record uses '\+all'"
        }
    }

    Context 'Get-AcceptedDomain throws' {
        BeforeAll {
            Mock Get-AcceptedDomain { throw 'Unauthorized' }
        }

        It 'Returns a single Fail carrying the retrieval error' {
            $results = & $checkFile
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'High'
            $results[0].AffectedObject | Should -Be 'Accepted Domains'
            $results[0].Error | Should -Match 'Unauthorized'
        }
    }
}
