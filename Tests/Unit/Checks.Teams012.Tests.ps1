BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"

    # Stub Teams cmdlet needed by Teams012
    function Get-CsTeamsCallingPolicy { [CmdletBinding()] param() }
}

Describe 'MET-Teams012 Call Reporting' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'Teams' 'MET-Teams012-CallReporting.ps1'
    }

    Context 'all policies have call reporting enabled' {
        BeforeAll {
            Mock Get-CsTeamsCallingPolicy {
                @(
                    [PSCustomObject]@{ Identity = 'Global'; ReportCall = 'Enabled' },
                    [PSCustomObject]@{ Identity = 'Tag:Restricted'; ReportCall = 'Enabled' }
                )
            }
        }
        It 'Returns Pass' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
        }
    }

    Context 'one policy has call reporting disabled' {
        BeforeAll {
            Mock Get-CsTeamsCallingPolicy {
                @(
                    [PSCustomObject]@{ Identity = 'Global'; ReportCall = 'Enabled' },
                    [PSCustomObject]@{ Identity = 'Tag:NoReporting'; ReportCall = 'Disabled' }
                )
            }
        }
        It 'Returns Fail naming the disabled policy' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Finding | Should -Match 'Tag:NoReporting'
            $results[0].Finding | Should -Not -Match 'Global'
        }
    }

    Context 'multiple policies have call reporting disabled' {
        BeforeAll {
            Mock Get-CsTeamsCallingPolicy {
                @(
                    [PSCustomObject]@{ Identity = 'Tag:NoReporting1'; ReportCall = 'Disabled' },
                    [PSCustomObject]@{ Identity = 'Tag:NoReporting2'; ReportCall = 'Disabled' }
                )
            }
        }
        It 'Returns Fail naming all disabled policies' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Finding | Should -Match 'Tag:NoReporting1'
            $results[0].Finding | Should -Match 'Tag:NoReporting2'
        }
    }

    Context 'ReportCall is absent from every policy' {
        BeforeAll {
            Mock Get-CsTeamsCallingPolicy {
                @(
                    [PSCustomObject]@{ Identity = 'Global' },
                    [PSCustomObject]@{ Identity = 'Tag:Restricted' }
                )
            }
        }
        It 'Returns NotApplicable rather than Pass, naming the property and recording why' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'NotApplicable'
            $results[0].Finding | Should -Match 'ReportCall'
            $results[0].Error | Should -Not -BeNullOrEmpty
            $results[0].Error | Should -Match 'ReportCall'
        }
    }

    Context 'ReportCall is present on one policy and absent on another' {
        BeforeAll {
            Mock Get-CsTeamsCallingPolicy {
                @(
                    [PSCustomObject]@{ Identity = 'Global'; ReportCall = 'Enabled' },
                    [PSCustomObject]@{ Identity = 'Tag:Unknown' }
                )
            }
        }
        It 'Returns Warning naming the policy whose property was absent' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'ReportCall'
            $results[0].Finding | Should -Match 'Tag:Unknown'
        }
    }

    Context 'ReportCall is null on one policy and disabled on another' {
        BeforeAll {
            Mock Get-CsTeamsCallingPolicy {
                @(
                    [PSCustomObject]@{ Identity = 'Tag:NoReporting'; ReportCall = 'Disabled' },
                    [PSCustomObject]@{ Identity = 'Tag:Unknown'; ReportCall = $null }
                )
            }
        }
        It 'Returns Fail and still reports the policy whose property was absent' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Finding | Should -Match 'Tag:NoReporting'
            $results[0].Finding | Should -Match 'Tag:Unknown'
        }
    }

    Context 'cmdlet throws (module absent)' {
        BeforeAll {
            Mock Get-CsTeamsCallingPolicy { throw 'Teams calling policy unavailable' }
        }
        It 'Returns Fail with ErrorMessage populated' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Error | Should -Match 'Teams calling policy unavailable'
        }
    }
}
