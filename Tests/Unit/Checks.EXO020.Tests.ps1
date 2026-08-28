BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"

    function Get-HostedConnectionFilterPolicy { [CmdletBinding()] param() }
}

Describe 'MET-EXO020 Connection Filter Policy Hygiene' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'EXO' 'MET-EXO020-ConnectionFilterPolicy.ps1'
    }

    Context 'Allow list empty and safe list disabled' {
        BeforeAll {
            Mock Get-HostedConnectionFilterPolicy {
                [PSCustomObject]@{
                    Name           = 'Default'
                    IsDefault      = $true
                    IPAllowList    = @()
                    IPBlockList    = @('198.51.100.7')
                    EnableSafeList = $false
                }
            }
        }

        It 'Returns Pass' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Pass'
            $results[0].Severity | Should -Be 'High'
            $results[0].CheckId | Should -Be 'MET-EXO020'
            $results[0].AffectedObject | Should -Be 'Default (default)'
            $results[0].Finding | Should -Match 'allow list is empty'
        }
    }

    Context 'Allow list has entries' {
        BeforeAll {
            Mock Get-HostedConnectionFilterPolicy {
                [PSCustomObject]@{
                    Name           = 'Default'
                    IsDefault      = $true
                    IPAllowList    = @('203.0.113.10', '198.51.100.0/25')
                    IPBlockList    = @()
                    EnableSafeList = $false
                }
            }
        }

        It 'Returns Fail naming the entries' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'High'
            $results[0].Finding | Should -Match 'IP allow list contains 2 entries'
            $results[0].Finding | Should -Match '203\.0\.113\.10'
            $results[0].Finding | Should -Match 'skips spam filtering and spoof intelligence'
            $results[0].Metadata.IPAllowListCount | Should -Be 2
        }

        It 'Does not flag a /25 as broad' {
            $results = @(& $checkFile)
            $results[0].Finding | Should -Not -Match 'broad CIDR ranges'
            $results[0].Metadata.BroadAllowEntryCount | Should -Be 0
        }
    }

    Context 'Allow list contains broad CIDR ranges' {
        BeforeAll {
            Mock Get-HostedConnectionFilterPolicy {
                [PSCustomObject]@{
                    Name           = 'Default'
                    IsDefault      = $true
                    IPAllowList    = @('203.0.113.0/16', '198.51.100.0/8', '192.0.2.55')
                    IPBlockList    = @()
                    EnableSafeList = $false
                }
            }
        }

        It 'Adds a distinct broad-range issue naming the entries' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Fail'
            $results[0].Finding | Should -Match '2 of those allow-list entries are broad CIDR ranges'
            $results[0].Finding | Should -Match '203\.0\.113\.0/16'
            $results[0].Finding | Should -Match '198\.51\.100\.0/8'
            $results[0].Metadata.BroadAllowEntryCount | Should -Be 2
        }
    }

    Context 'Allow list contains unparseable and non-IPv4 entries' {
        BeforeAll {
            Mock Get-HostedConnectionFilterPolicy {
                [PSCustomObject]@{
                    Name           = 'Default'
                    IsDefault      = $true
                    IPAllowList    = @('203.0.113.1-203.0.113.40', '2001:db8::/32', 'not-an-ip/8', '203.0.113.0/abc', '203.0.113.0/99')
                    IPBlockList    = @()
                    EnableSafeList = $false
                }
            }
        }

        It 'Fails on the allow list without throwing or reporting broad ranges' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Fail'
            $results[0].Error | Should -BeNullOrEmpty
            $results[0].Finding | Should -Not -Match 'broad CIDR ranges'
            $results[0].Metadata.BroadAllowEntryCount | Should -Be 0
        }
    }

    Context 'Allow list exceeds ten entries' {
        BeforeAll {
            Mock Get-HostedConnectionFilterPolicy {
                [PSCustomObject]@{
                    Name           = 'Default'
                    IsDefault      = $true
                    IPAllowList    = @(1..12 | ForEach-Object { "203.0.113.$_" })
                    IPBlockList    = @()
                    EnableSafeList = $false
                }
            }
        }

        It 'Truncates the listed entries to ten' {
            $results = @(& $checkFile)
            $results[0].Finding | Should -Match '\(\+2 more\)'
            $results[0].Metadata.IPAllowListCount | Should -Be 12
        }
    }

    Context 'Safe list enabled with an empty allow list' {
        BeforeAll {
            Mock Get-HostedConnectionFilterPolicy {
                [PSCustomObject]@{
                    Name           = 'Default'
                    IsDefault      = $true
                    IPAllowList    = @()
                    IPBlockList    = @()
                    EnableSafeList = $true
                }
            }
        }

        It 'Returns Warning' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Warning'
            $results[0].Severity | Should -Be 'High'
            $results[0].Finding | Should -Match 'EnableSafeList'
            $results[0].Finding | Should -Match 'cannot be enumerated or audited'
        }
    }

    Context 'Safe list enabled together with allow list entries' {
        BeforeAll {
            Mock Get-HostedConnectionFilterPolicy {
                [PSCustomObject]@{
                    Name           = 'Default'
                    IsDefault      = $true
                    IPAllowList    = @('203.0.113.10')
                    IPBlockList    = @()
                    EnableSafeList = $true
                }
            }
        }

        It 'Returns Fail, with the safe list reported as an additional issue' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Fail'
            $results[0].Finding | Should -Match 'IP allow list contains 1 entry'
            $results[0].Finding | Should -Match 'EnableSafeList'
        }
    }

    Context 'Properties are missing or null' {
        BeforeAll {
            Mock Get-HostedConnectionFilterPolicy {
                [PSCustomObject]@{ Name = 'Legacy Policy' }
            }
        }

        It 'Treats missing properties as empty and returns Pass' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Pass'
            $results[0].Severity | Should -Be 'High'
            $results[0].AffectedObject | Should -Be 'Legacy Policy'
            $results[0].Error | Should -BeNullOrEmpty
        }
    }

    Context 'Multiple policies' {
        BeforeAll {
            Mock Get-HostedConnectionFilterPolicy {
                @(
                    [PSCustomObject]@{ Name = 'Default'; IsDefault = $true; IPAllowList = @(); IPBlockList = @(); EnableSafeList = $false }
                    [PSCustomObject]@{ Name = 'Custom'; IsDefault = $false; IPAllowList = @('203.0.113.0/8'); IPBlockList = @(); EnableSafeList = $false }
                )
            }
        }

        It 'Emits one result per policy' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 2
            $results[0].Result | Should -Be 'Pass'
            $results[1].Result | Should -Be 'Fail'
            $results[1].AffectedObject | Should -Be 'Custom'
        }
    }

    Context 'No policies returned' {
        BeforeAll {
            Mock Get-HostedConnectionFilterPolicy { @() }
        }

        It 'Returns a single Info result' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Info'
            $results[0].Severity | Should -Be 'High'
        }
    }

    Context 'Get-HostedConnectionFilterPolicy throws' {
        BeforeAll {
            Mock Get-HostedConnectionFilterPolicy { throw 'Access denied' }
        }

        It 'Returns Fail with error message populated' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'High'
            $results[0].CheckId | Should -Be 'MET-EXO020'
            $results[0].Error | Should -Not -BeNullOrEmpty
            $results[0].Error | Should -Match 'Access denied'
        }
    }
}
