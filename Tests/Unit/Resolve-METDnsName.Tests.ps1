BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/Resolve-METDnsName.ps1"
}

Describe 'Resolve-METDnsName' {
    Context 'when local DNS utilities are unavailable' {
        BeforeEach {
            Mock Get-Command { $null } -ParameterFilter {
                $Name -in @('dig', 'nslookup') -and $CommandType -eq 'Application'
            }
        }

        It 'uses DNS-over-HTTPS and returns Resolve-DnsName-compatible TXT records' {
            Mock Invoke-RestMethod {
                [PSCustomObject]@{
                    Status = 0
                    Answer = @(
                        [PSCustomObject]@{ type = 16; TTL = 3600; data = '"v=spf1 include:spf.protection.outlook.com -all"' }
                    )
                }
            }

            $result = Resolve-METDnsName -Name 'contoso.com' -Type TXT

            $result | Should -HaveCount 1
            $result[0].Strings[0] | Should -Be 'v=spf1 include:spf.protection.outlook.com -all'
            $result[0].TTL | Should -Be 3600
            Should -Invoke Invoke-RestMethod -Times 1 -ParameterFilter {
                $Uri -eq 'https://dns.google/resolve?name=contoso.com&type=TXT'
            }
        }

        It 'returns no records for an authoritative NXDOMAIN response' {
            Mock Invoke-RestMethod { [PSCustomObject]@{ Status = 3; Answer = @() } }

            @(Resolve-METDnsName -Name 'missing.contoso.com' -Type TXT) | Should -HaveCount 0
        }

        It 'throws when the fallback resolver is unavailable' {
            Mock Invoke-RestMethod { throw 'network unavailable' }

            { Resolve-METDnsName -Name 'contoso.com' -Type TXT } |
                Should -Throw '*DNS-over-HTTPS fallback*network unavailable*'
        }
    }
}

Describe 'Resolve-METDnsName DNS-over-HTTPS disclosure and control' {
    BeforeEach {
        Set-Variable -Name METDohWarned -Scope Script -Value $false -ErrorAction SilentlyContinue
        Remove-Item Env:\MET_DOH_RESOLVER -ErrorAction SilentlyContinue
    }

    AfterAll {
        Remove-Item Env:\MET_DOH_RESOLVER -ErrorAction SilentlyContinue
    }

    Context 'The DoH tier is reached' {
        BeforeEach {
            Mock Get-Command { $null } -ParameterFilter {
                $Name -in @('dig', 'nslookup') -and $CommandType -eq 'Application'
            }
            Mock Invoke-RestMethod { [PSCustomObject]@{ Status = 0; Answer = @() } }
        }

        It 'Warns once, naming the provider' {
            $warnings = @()
            Resolve-METDnsName -Name 'contoso.com' -Type TXT -WarningVariable warnings -WarningAction SilentlyContinue
            ($warnings -join ' ') | Should -Match 'dns\.google'
        }

        It 'Does not warn again in the same session' {
            Resolve-METDnsName -Name 'contoso.com' -Type TXT -WarningAction SilentlyContinue | Out-Null
            $warnings = @()
            Resolve-METDnsName -Name 'fabrikam.com' -Type TXT -WarningVariable warnings -WarningAction SilentlyContinue | Out-Null
            ($warnings | Where-Object { $_ -match 'dns\.google' }) | Should -BeNullOrEmpty
        }

        It 'Bounds the request with a timeout' {
            Resolve-METDnsName -Name 'contoso.com' -Type TXT -WarningAction SilentlyContinue | Out-Null
            Should -Invoke Invoke-RestMethod -Exactly 1 -ParameterFilter { $TimeoutSec -eq 15 }
        }
    }

    Context 'MET_DOH_RESOLVER is none' {
        BeforeEach {
            Mock Get-Command { $null } -ParameterFilter {
                $Name -in @('dig', 'nslookup') -and $CommandType -eq 'Application'
            }
            Mock Invoke-RestMethod { throw 'the network must not be reached' }
        }

        It 'Throws without issuing a request' {
            $env:MET_DOH_RESOLVER = 'none'
            { Resolve-METDnsName -Name 'contoso.com' -Type TXT } | Should -Throw -ExpectedMessage '*MET_DOH_RESOLVER*'
            Should -Invoke Invoke-RestMethod -Exactly 0
        }
    }
}
