BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"

    function Get-RemoteDomain { [CmdletBinding()] param() }
}

Describe 'MET-EXO018 Remote Domain Automatic Forwarding' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'EXO' 'MET-EXO018-RemoteDomainForwarding.ps1'
    }

    Context 'Default remote domain has automatic forwarding disabled' {
        BeforeAll {
            Mock Get-RemoteDomain {
                [PSCustomObject]@{ Name = 'Default'; DomainName = '*'; AutoForwardEnabled = $false }
            }
        }

        It 'Returns Pass' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Pass'
            $results[0].Severity | Should -Be 'High'
            $results[0].CheckId | Should -Be 'MET-EXO018'
            $results[0].Finding | Should -Match 'disabled for this remote domain'
        }
    }

    Context 'Default remote domain has automatic forwarding enabled' {
        BeforeAll {
            Mock Get-RemoteDomain {
                [PSCustomObject]@{ Name = 'Default'; DomainName = '*'; AutoForwardEnabled = $true }
            }
        }

        It 'Returns Fail with High severity' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'High'
            $results[0].CheckId | Should -Be 'MET-EXO018'
            $results[0].Finding | Should -Match 'tenant-wide default remote domain'
            $results[0].AffectedObject | Should -Match 'Default'
        }

        It 'Recommends Set-RemoteDomain and names the other two control planes' {
            $results = @(& $checkFile)
            $results[0].Recommendation | Should -Match 'Set-RemoteDomain'
            $results[0].Recommendation | Should -Match 'MET-MDO007'
            $results[0].Recommendation | Should -Match 'MET-EXO012'
        }
    }

    Context 'Specific remote domain has automatic forwarding enabled' {
        BeforeAll {
            Mock Get-RemoteDomain {
                [PSCustomObject]@{ Name = 'Partner'; DomainName = 'partner.example.com'; AutoForwardEnabled = $true }
            }
        }

        It 'Returns Warning' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Warning'
            $results[0].Severity | Should -Be 'High'
            $results[0].Finding | Should -Match 'partner\.example\.com'
            $results[0].Finding | Should -Match 'scoped exception'
        }
    }

    Context 'Multiple remote domains with mixed configuration' {
        BeforeAll {
            Mock Get-RemoteDomain {
                @(
                    [PSCustomObject]@{ Name = 'Default'; DomainName = '*'; AutoForwardEnabled = $true }
                    [PSCustomObject]@{ Name = 'Partner'; DomainName = 'partner.example.com'; AutoForwardEnabled = $true }
                    [PSCustomObject]@{ Name = 'Vendor'; DomainName = 'vendor.example.com'; AutoForwardEnabled = $false }
                )
            }
        }

        It 'Returns one result per remote domain' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 3
        }

        It 'Grades the tenant-wide default as Fail and the scoped domain as Warning' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Fail'
            $results[1].Result | Should -Be 'Warning'
            $results[2].Result | Should -Be 'Pass'
        }

        It 'Uses the same severity on every result' {
            $results = @(& $checkFile)
            @($results | Select-Object -ExpandProperty Severity -Unique) | Should -Be 'High'
        }
    }

    Context 'AutoForwardEnabled property is null' {
        BeforeAll {
            Mock Get-RemoteDomain {
                [PSCustomObject]@{ Name = 'Default'; DomainName = '*'; AutoForwardEnabled = $null }
            }
        }

        It 'Returns Pass and states the property was absent' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Pass'
            $results[0].Severity | Should -Be 'High'
            $results[0].Finding | Should -Match 'absent or null'
        }
    }

    Context 'AutoForwardEnabled property is missing from the object' {
        BeforeAll {
            Mock Get-RemoteDomain {
                [PSCustomObject]@{ Name = 'Default'; DomainName = '*' }
            }
        }

        It 'Returns Pass and states the property was absent' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Pass'
            $results[0].Finding | Should -Match 'absent or null'
        }
    }

    Context 'No remote domains are returned' {
        BeforeAll {
            Mock Get-RemoteDomain { @() }
        }

        It 'Returns a single Info result' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Info'
            $results[0].Severity | Should -Be 'High'
            $results[0].Finding | Should -Match 'No remote domains are configured'
        }
    }

    Context 'Get-RemoteDomain throws' {
        BeforeAll {
            Mock Get-RemoteDomain { throw 'Access denied' }
        }

        It 'Returns Fail with the error message populated' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'High'
            $results[0].AffectedObject | Should -Be 'Remote Domains'
            $results[0].Error | Should -Not -BeNullOrEmpty
            $results[0].Error | Should -Match 'Access denied'
        }
    }
}
