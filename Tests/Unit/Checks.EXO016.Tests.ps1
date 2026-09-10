BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"

    function Get-ArcConfig { [CmdletBinding()] param() }
}

Describe 'MET-EXO016 ARC Trusted Sealers' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'EXO' 'MET-EXO016-ArcTrustedSealers.ps1'
    }

    # The real Get-ArcConfig behaviour: "If no trusted ARC sealers are configured, the
    # command returns no results." An empty return is the documented "none configured"
    # signal, not an unreadable state - it must not surface as NotApplicable + Error.
    Context 'Get-ArcConfig returns nothing (no sealers configured)' {
        BeforeAll {
            Mock Get-ArcConfig { }
        }

        It 'Returns Info, not NotApplicable, and does not populate Error' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Info'
            $results[0].Severity | Should -Be 'Low'
            $results[0].Finding | Should -Match 'no trusted ARC sealers are configured'
            $results[0].Error | Should -BeNullOrEmpty
        }
    }

    Context 'an object with an empty ArcTrustedSealers list' {
        BeforeAll {
            Mock Get-ArcConfig {
                [PSCustomObject]@{ ArcTrustedSealers = @() }
            }
        }

        It 'Returns Info with no sealers message' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Info'
            $results[0].Severity | Should -Be 'Low'
            $results[0].Finding | Should -Match 'No ARC trusted sealers configured'
        }
    }

    Context 'ArcTrustedSealers is present but null' {
        BeforeAll {
            Mock Get-ArcConfig {
                [PSCustomObject]@{ ArcTrustedSealers = $null }
            }
        }

        It 'Returns NotApplicable because a null value was never observed as an empty list' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'NotApplicable'
            $results[0].Severity | Should -Be 'Low'
            $results[0].Finding | Should -Match 'not established'
            $results[0].Error | Should -Not -BeNullOrEmpty
        }
    }

    Context 'trusted sealers configured' {
        BeforeAll {
            Mock Get-ArcConfig {
                [PSCustomObject]@{ ArcTrustedSealers = @('vendor-a.com', 'vendor-b.com') }
            }
        }

        It 'Returns Info with sealer domains listed' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Info'
            $results[0].Severity | Should -Be 'Low'
            $results[0].Finding | Should -Match 'vendor-a.com'
            $results[0].Finding | Should -Match 'vendor-b.com'
            $results[0].Finding | Should -Match '2 ARC trusted sealer'
        }
    }

    Context 'single trusted sealer configured' {
        BeforeAll {
            Mock Get-ArcConfig {
                [PSCustomObject]@{ ArcTrustedSealers = @('mail-gateway.com') }
            }
        }

        It 'Returns Info with sealer domain listed' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Info'
            $results[0].Severity | Should -Be 'Low'
            $results[0].Finding | Should -Match 'mail-gateway.com'
            $results[0].Finding | Should -Match '1 ARC trusted sealer'
        }
    }

    Context 'Get-ArcConfig throws' {
        BeforeAll {
            Mock Get-ArcConfig { throw 'Access Denied' }
        }

        It 'Returns Fail with Error populated' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'Low'
            $results[0].Finding | Should -Match 'Unable to retrieve ARC configuration'
            $results[0].Error | Should -Not -BeNullOrEmpty
            $results[0].Error | Should -Match 'Access Denied'
        }
    }

    Context 'The ARC configuration omits the ArcTrustedSealers property' {
        BeforeAll {
            Mock Get-ArcConfig {
                [PSCustomObject]@{ Identity = 'Default' }
            }
        }

        It 'Does not return Pass on a list it never read' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Not -Be 'Pass'
            $results[0].AffectedObject | Should -Be 'ARC Trusted Sealers'
        }

        It 'States the property was not returned rather than that nothing is configured' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'NotApplicable'
            $results[0].Finding | Should -Not -Match 'No ARC trusted sealers configured'
            $results[0].Finding | Should -Match 'not established'
            $results[0].Error | Should -Not -BeNullOrEmpty
        }
    }
}
