BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"

    function Get-QuarantinePolicy { [CmdletBinding()] param([string]$QuarantinePolicyType) }
}

Describe 'MET-EXO017 Quarantine Notification Cadence' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'EXO' 'MET-EXO017-QuarantineNotificationCadence.ps1'
    }

    Context '4-hour cadence' {
        BeforeAll {
            Mock Get-QuarantinePolicy {
                [PSCustomObject]@{ EndUserSpamNotificationFrequency = [TimeSpan]::Parse('04:00:00') }
            }
        }

        It 'Returns Info mentioning 4 hours' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Info'
            $results[0].Severity | Should -Be 'Informational'
            $results[0].Finding | Should -Match '4 hours'
        }
    }

    Context '1-day cadence' {
        BeforeAll {
            Mock Get-QuarantinePolicy {
                [PSCustomObject]@{ EndUserSpamNotificationFrequency = [TimeSpan]::Parse('1.00:00:00') }
            }
        }

        It 'Returns Info mentioning 1 day' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Info'
            $results[0].Severity | Should -Be 'Informational'
            $results[0].Finding | Should -Match '1 day'
        }
    }

    Context '7-day cadence' {
        BeforeAll {
            Mock Get-QuarantinePolicy {
                [PSCustomObject]@{ EndUserSpamNotificationFrequency = [TimeSpan]::Parse('7.00:00:00') }
            }
        }

        It 'Returns Info mentioning 7 days or week' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Info'
            $results[0].Severity | Should -Be 'Informational'
            $results[0].Finding | Should -Match '7 days|week'
        }
    }

    Context 'multiple objects returned - takes first' {
        BeforeAll {
            Mock Get-QuarantinePolicy {
                @(
                    [PSCustomObject]@{ EndUserSpamNotificationFrequency = [TimeSpan]::Parse('04:00:00') },
                    [PSCustomObject]@{ EndUserSpamNotificationFrequency = [TimeSpan]::Parse('7.00:00:00') }
                )
            }
        }

        It 'Returns Info using the first object only' {
            $results = & $checkFile
            $results.Count | Should -Be 1
            $results[0].Finding | Should -Match '4 hours'
        }
    }

    Context 'unrecognized or null TimeSpan' {
        BeforeAll {
            Mock Get-QuarantinePolicy {
                [PSCustomObject]@{ EndUserSpamNotificationFrequency = $null }
            }
        }

        It 'Returns Info noting it could not be determined, without crashing' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Info'
            $results[0].Finding | Should -Match 'could not be determined'
        }
    }

    Context 'unrecognized non-standard TimeSpan value' {
        BeforeAll {
            Mock Get-QuarantinePolicy {
                [PSCustomObject]@{ EndUserSpamNotificationFrequency = [TimeSpan]::Parse('02:30:00') }
            }
        }

        It 'Returns Info noting it could not be determined, without crashing' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Info'
            $results[0].Finding | Should -Match 'could not be determined'
        }
    }

    Context 'Get-QuarantinePolicy throws' {
        BeforeAll {
            Mock Get-QuarantinePolicy { throw 'Access Denied' }
        }

        It 'Returns Fail with Error populated' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'Low'
            $results[0].Finding | Should -Match 'Unable to retrieve'
            $results[0].Error | Should -Not -BeNullOrEmpty
            $results[0].Error | Should -Match 'Access Denied'
        }
    }
}
