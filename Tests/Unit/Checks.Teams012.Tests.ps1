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

Describe 'MET-Teams012 PSTN Call Spam Filtering' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'Teams' 'MET-Teams012-CallReporting.ps1'
    }

    Context 'spam filtering is enabled in every policy' {
        BeforeAll {
            Mock Get-CsTeamsCallingPolicy {
                @(
                    [PSCustomObject]@{ Identity = 'Global'; ReportCall = 'Enabled'; SpamFilteringEnabledType = 'Enabled' },
                    [PSCustomObject]@{ Identity = 'Tag:Sales'; ReportCall = 'Enabled'; SpamFilteringEnabledType = 'Enabled' }
                )
            }
        }
        It 'Emits a separate Pass result after the call reporting result' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 2
            $results[0].Name | Should -Be 'Call Reporting'
            $results[1].Name | Should -Be 'PSTN Call Spam Filtering'
            $results[1].CheckId | Should -Be 'MET-Teams012'
            $results[1].Result | Should -Be 'Pass'
            $results[1].Severity | Should -Be 'Medium'
            $results[1].AffectedObject | Should -Be 'Teams Calling Policies'
        }
    }

    Context 'spam filtering is disabled in one policy' {
        BeforeAll {
            Mock Get-CsTeamsCallingPolicy {
                @(
                    [PSCustomObject]@{ Identity = 'Global'; ReportCall = 'Enabled'; SpamFilteringEnabledType = 'Enabled' },
                    [PSCustomObject]@{ Identity = 'Tag:NoSpam'; ReportCall = 'Enabled'; SpamFilteringEnabledType = 'Disabled' }
                )
            }
        }
        It 'Returns Fail naming only the disabled policy, leaving call reporting at Pass' {
            $results = @(& $checkFile)
            $spam = $results | Where-Object Name -eq 'PSTN Call Spam Filtering'
            $spam.Result | Should -Be 'Fail'
            $spam.Finding | Should -Match 'Tag:NoSpam'
            $spam.Finding | Should -Not -Match 'Global'
            $spam.Recommendation | Should -Match 'Set-CsTeamsCallingPolicy -Identity <name> -SpamFilteringEnabledType Enabled'
            ($results | Where-Object Name -eq 'Call Reporting').Result | Should -Be 'Pass'
        }
    }

    Context 'spam filtering carries an unrecognized value' {
        BeforeAll {
            Mock Get-CsTeamsCallingPolicy {
                @([PSCustomObject]@{ Identity = 'Global'; ReportCall = 'Enabled'; SpamFilteringEnabledType = 'Sometimes' })
            }
        }
        It 'Returns Warning naming the value' {
            $spam = @(& $checkFile) | Where-Object Name -eq 'PSTN Call Spam Filtering'
            $spam.Result | Should -Be 'Warning'
            $spam.Finding | Should -Match "'Sometimes'"
        }
    }

    Context 'spam filtering is absent from every policy' {
        BeforeAll {
            Mock Get-CsTeamsCallingPolicy {
                @([PSCustomObject]@{ Identity = 'Global'; ReportCall = 'Enabled' })
            }
        }
        It 'Returns NotApplicable with the reason recorded, never Pass' {
            $spam = @(& $checkFile) | Where-Object Name -eq 'PSTN Call Spam Filtering'
            $spam.Result | Should -Be 'NotApplicable'
            $spam.Error | Should -Match 'SpamFilteringEnabledType'
            $spam.Finding | Should -Match 'rather than a pass'
        }
    }

    Context 'spam filtering is absent on one policy only' {
        BeforeAll {
            Mock Get-CsTeamsCallingPolicy {
                @(
                    [PSCustomObject]@{ Identity = 'Global'; ReportCall = 'Enabled'; SpamFilteringEnabledType = 'Enabled' },
                    [PSCustomObject]@{ Identity = 'Tag:Unknown'; ReportCall = 'Enabled' }
                )
            }
        }
        It 'Returns Warning naming the policy whose property was absent' {
            $spam = @(& $checkFile) | Where-Object Name -eq 'PSTN Call Spam Filtering'
            $spam.Result | Should -Be 'Warning'
            $spam.Finding | Should -Match 'Tag:Unknown'
        }
    }

    Context 'ReportCall is absent everywhere but spam filtering is enabled' {
        BeforeAll {
            Mock Get-CsTeamsCallingPolicy {
                @([PSCustomObject]@{ Identity = 'Global'; SpamFilteringEnabledType = 'Enabled' })
            }
        }
        It 'Still assesses spam filtering after the call reporting NotApplicable' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 2
            ($results | Where-Object Name -eq 'Call Reporting').Result | Should -Be 'NotApplicable'
            ($results | Where-Object Name -eq 'PSTN Call Spam Filtering').Result | Should -Be 'Pass'
        }
    }

    Context 'cmdlet throws' {
        BeforeAll {
            Mock Get-CsTeamsCallingPolicy { throw 'Teams calling policy unavailable' }
        }
        It 'Returns the single retrieval Fail rather than one per setting' {
            @(& $checkFile).Count | Should -Be 1
        }
    }
}
