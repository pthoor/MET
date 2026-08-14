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
