BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"

    # Every DNS name this check resolves goes through Resolve-METDnsName, which is
    # stubbed here and mocked per-Context. No test in this file touches a resolver.
    function Get-AcceptedDomain  { [CmdletBinding()] param() }
    function Resolve-METDnsName  { [CmdletBinding()] param([string]$Name,[string]$Type) }
}

Describe 'MET-EXO001 DMARC' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'EXO' 'MET-EXO001-DMARC.ps1'
    }

    Context 'mail.onmicrosoft.com accepted domain' {
        BeforeAll {
            Mock Get-AcceptedDomain {
                [PSCustomObject]@{ DomainName = 'contoso.mail.onmicrosoft.com'; Default = $true; DomainType = 'Authoritative' }
            }
            Mock Resolve-METDnsName { throw 'a Microsoft-managed service domain must never be resolved' }
        }

        It 'Returns NotApplicable' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'NotApplicable'
            $results[0].Severity | Should -Be 'Informational'
        }

        It 'Never resolves DNS for a Microsoft-managed service domain' {
            $null = & $checkFile
            Should -Invoke Resolve-METDnsName -Times 0 -Exactly
        }
    }

    Context 'onmicrosoft domain without DMARC record' {
        BeforeAll {
            Mock Get-AcceptedDomain {
                [PSCustomObject]@{ DomainName = 'contoso.onmicrosoft.com'; Default = $true; DomainType = 'Authoritative' }
            }
            Mock Resolve-METDnsName { throw 'DNS name not found' }
        }

        It 'Returns Warning with the lookup error instead of a false Fail' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Severity | Should -Be 'High'
            $results[0].Finding | Should -Match 'DNS lookup failed'
            $results[0].Error | Should -Match 'DNS name not found'
        }
    }

    Context 'No DMARC TXT record is published' {
        BeforeAll {
            Mock Get-AcceptedDomain {
                [PSCustomObject]@{ DomainName = 'contoso.com'; Default = $true; DomainType = 'Authoritative' }
            }
            Mock Resolve-METDnsName { @() }
        }

        It 'Returns Fail naming the absent record' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'High'
            $results[0].AffectedObject | Should -Be 'contoso.com'
            $results[0].Finding | Should -Be 'No DMARC TXT record found'
        }

        It 'Recommends publishing the record at _dmarc for a customer-managed domain' {
            $results = & $checkFile
            $results[0].Recommendation | Should -Match '_dmarc\.contoso\.com'
            $results[0].Recommendation | Should -Not -Match 'admin center'
        }
    }

    Context 'No DMARC TXT record is published for an onmicrosoft.com domain' {
        BeforeAll {
            Mock Get-AcceptedDomain {
                [PSCustomObject]@{ DomainName = 'contoso.onmicrosoft.com'; Default = $true; DomainType = 'Authoritative' }
            }
            Mock Resolve-METDnsName { @() }
        }

        It 'Points at the Microsoft 365 admin center rather than an external DNS zone' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'High'
            $results[0].Recommendation | Should -Match 'Microsoft 365 admin center'
            $results[0].Recommendation | Should -Match 'p=reject'
        }
    }

    Context 'DMARC policy is p=none' {
        BeforeAll {
            Mock Get-AcceptedDomain {
                [PSCustomObject]@{ DomainName = 'contoso.com'; Default = $true; DomainType = 'Authoritative' }
            }
            Mock Resolve-METDnsName {
                [PSCustomObject]@{ Strings = @('v=DMARC1; p=none; rua=mailto:dmarc@contoso.com') }
            }
        }

        It 'Returns Fail naming the monitoring-only policy that was actually found' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'High'
            $results[0].Finding | Should -Match "DMARC policy is 'none'"
            $results[0].Finding | Should -Match 'no enforcement'
        }

        It 'Does not also claim the reporting address is missing' {
            $results = & $checkFile
            $results[0].Finding | Should -Not -Match 'No aggregate reporting address'
            $results[0].Finding | Should -Match 'Record: v=DMARC1; p=none; rua=mailto:dmarc@contoso\.com'
        }
    }

    Context 'DMARC record carries no p= tag at all' {
        BeforeAll {
            Mock Get-AcceptedDomain {
                [PSCustomObject]@{ DomainName = 'contoso.com'; Default = $true; DomainType = 'Authoritative' }
            }
            Mock Resolve-METDnsName {
                [PSCustomObject]@{ Strings = @('v=DMARC1; rua=mailto:dmarc@contoso.com') }
            }
        }

        It 'Returns Fail for a missing enforcement policy rather than for p=none' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'High'
            $results[0].Finding | Should -Match 'DMARC policy is not set to quarantine or reject'
            $results[0].Finding | Should -Not -Match "DMARC policy is 'none'"
        }
    }

    Context 'Enforcing DMARC policy with no rua= reporting address' {
        BeforeAll {
            Mock Get-AcceptedDomain {
                [PSCustomObject]@{ DomainName = 'contoso.com'; Default = $true; DomainType = 'Authoritative' }
            }
            Mock Resolve-METDnsName {
                [PSCustomObject]@{ Strings = @('v=DMARC1; p=quarantine') }
            }
        }

        It 'Returns Fail naming the missing aggregate reporting address only' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'High'
            $results[0].Finding | Should -Match 'No aggregate reporting address \(rua=\) configured'
            $results[0].Finding | Should -Not -Match 'DMARC policy is'
            $results[0].Finding | Should -Match 'Record: v=DMARC1; p=quarantine'
        }
    }

    Context 'DMARC policy is p=reject with reporting configured' {
        BeforeAll {
            Mock Get-AcceptedDomain {
                [PSCustomObject]@{ DomainName = 'contoso.com'; Default = $true; DomainType = 'Authoritative' }
            }
            Mock Resolve-METDnsName {
                [PSCustomObject]@{ Strings = @('v=DMARC1; p=reject; rua=mailto:dmarc@contoso.com') }
            }
        }

        It 'Returns Pass quoting the enforcing record it read' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
            $results[0].Severity | Should -Be 'High'
            $results[0].AffectedObject | Should -Be 'contoso.com'
            $results[0].Finding | Should -Match 'enforcement policy and reporting configured'
            $results[0].Finding | Should -Match 'Record: v=DMARC1; p=reject; rua=mailto:dmarc@contoso\.com'
        }
    }

    Context 'DMARC policy is p=quarantine with reporting configured' {
        BeforeAll {
            Mock Get-AcceptedDomain {
                [PSCustomObject]@{ DomainName = 'contoso.com'; Default = $true; DomainType = 'Authoritative' }
            }
            Mock Resolve-METDnsName {
                [PSCustomObject]@{ Strings = @('v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc@contoso.com') }
            }
        }

        It 'Accepts quarantine as an enforcement policy' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
            $results[0].Severity | Should -Be 'High'
            $results[0].Finding | Should -Match 'Record: v=DMARC1; p=quarantine; pct=100'
        }
    }

    Context 'A TXT record set that also holds unrelated records' {
        BeforeAll {
            Mock Get-AcceptedDomain {
                [PSCustomObject]@{ DomainName = 'contoso.com'; Default = $true; DomainType = 'Authoritative' }
            }
            Mock Resolve-METDnsName {
                @(
                    [PSCustomObject]@{ Strings = @('MS=ms12345678') }
                    [PSCustomObject]@{ Strings = @('v=DMARC1; p=reject; rua=mailto:dmarc@contoso.com') }
                )
            }
        }

        It 'Selects the DMARC record and ignores the rest' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
            $results[0].Finding | Should -Not -Match 'ms12345678'
        }
    }

    Context 'Several accepted domains with different DMARC postures' {
        BeforeAll {
            Mock Get-AcceptedDomain {
                @(
                    [PSCustomObject]@{ DomainName = 'contoso.com'; Default = $true; DomainType = 'Authoritative' }
                    [PSCustomObject]@{ DomainName = 'fabrikam.com'; Default = $false; DomainType = 'Authoritative' }
                )
            }
            Mock Resolve-METDnsName {
                param([string]$Name, [string]$Type)

                if ($Name -eq '_dmarc.contoso.com') {
                    return [PSCustomObject]@{ Strings = @('v=DMARC1; p=reject; rua=mailto:dmarc@contoso.com') }
                }
                return [PSCustomObject]@{ Strings = @('v=DMARC1; p=none; rua=mailto:dmarc@fabrikam.com') }
            }
        }

        It 'Reports one result per domain, each naming its own policy' {
            $results = & $checkFile
            $results.Count | Should -Be 2

            $contoso = $results | Where-Object { $_.AffectedObject -eq 'contoso.com' }
            $contoso.Result | Should -Be 'Pass'

            $fabrikam = $results | Where-Object { $_.AffectedObject -eq 'fabrikam.com' }
            $fabrikam.Result | Should -Be 'Fail'
            $fabrikam.Finding | Should -Match "DMARC policy is 'none'"
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
