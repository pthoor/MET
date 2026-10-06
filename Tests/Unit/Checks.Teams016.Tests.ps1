BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"

    function Get-CsTeamsMessagingConfiguration { [CmdletBinding()] param() }

    function Get-Teams016Result {
        param($Results, [string]$Property)
        @($Results | Where-Object { $_.AffectedObject -eq "Teams Messaging Configuration ($Property)" })
    }
}

Describe 'MET-Teams016 Teams Messaging Safety' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'Teams' 'MET-Teams016-MessagingSafety.ps1'
    }

    Context 'every messaging safety setting is Enabled' {
        BeforeAll {
            Mock Get-CsTeamsMessagingConfiguration {
                [PSCustomObject]@{
                    Identity                          = 'Global'
                    FileTypeCheck                     = 'Enabled'
                    UrlReputationCheck                = 'Enabled'
                    ReportIncorrectSecurityDetections = 'Enabled'
                }
            }
        }

        It 'Returns one Pass per setting' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 3
            $results | ForEach-Object { $_.Result | Should -Be 'Pass' }
            $results | ForEach-Object { $_.CheckId | Should -Be 'MET-Teams016' }
            $results | ForEach-Object { $_.Category | Should -Be 'Teams' }
            $results | ForEach-Object { $_.Name | Should -Be 'Teams Messaging Safety' }
        }

        It 'Grades each setting at its own severity' {
            $results = @(& $checkFile)
            (Get-Teams016Result $results 'FileTypeCheck')[0].Severity | Should -Be 'High'
            (Get-Teams016Result $results 'UrlReputationCheck')[0].Severity | Should -Be 'Medium'
            (Get-Teams016Result $results 'ReportIncorrectSecurityDetections')[0].Severity | Should -Be 'Low'
        }
    }

    Context 'FileTypeCheck is Disabled' {
        BeforeAll {
            Mock Get-CsTeamsMessagingConfiguration {
                [PSCustomObject]@{
                    FileTypeCheck                     = 'Disabled'
                    UrlReputationCheck                = 'Enabled'
                    ReportIncorrectSecurityDetections = 'Enabled'
                }
            }
        }

        It 'Returns Fail at High severity naming weaponizable files and the fix' {
            $result = (Get-Teams016Result @(& $checkFile) 'FileTypeCheck')[0]
            $result.Result | Should -Be 'Fail'
            $result.Severity | Should -Be 'High'
            $result.Finding | Should -Match 'weaponizable'
            $result.Recommendation | Should -Match 'Set-CsTeamsMessagingConfiguration -Identity Global -FileTypeCheck Enabled'
        }
    }

    Context 'UrlReputationCheck is Disabled' {
        BeforeAll {
            Mock Get-CsTeamsMessagingConfiguration {
                [PSCustomObject]@{
                    FileTypeCheck                     = 'Enabled'
                    UrlReputationCheck                = 'Disabled'
                    ReportIncorrectSecurityDetections = 'Enabled'
                }
            }
        }

        It 'Returns Fail at Medium severity' {
            $result = (Get-Teams016Result @(& $checkFile) 'UrlReputationCheck')[0]
            $result.Result | Should -Be 'Fail'
            $result.Severity | Should -Be 'Medium'
            $result.Finding | Should -Match 'URL'
        }
    }

    Context 'ReportIncorrectSecurityDetections is Disabled' {
        BeforeAll {
            Mock Get-CsTeamsMessagingConfiguration {
                [PSCustomObject]@{
                    FileTypeCheck                     = 'Enabled'
                    UrlReputationCheck                = 'Enabled'
                    ReportIncorrectSecurityDetections = 'Disabled'
                }
            }
        }

        It 'Returns Warning rather than Fail, since it is a feedback channel not a protection' {
            $result = (Get-Teams016Result @(& $checkFile) 'ReportIncorrectSecurityDetections')[0]
            $result.Result | Should -Be 'Warning'
            $result.Severity | Should -Be 'Low'
        }
    }

    Context 'none of the settings is returned (GCC, GCC High, DoD, or an older module)' {
        BeforeAll {
            Mock Get-CsTeamsMessagingConfiguration {
                [PSCustomObject]@{ Identity = 'Global' }
            }
        }

        It 'Returns NotApplicable per setting with the reason recorded, never Pass' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 3
            foreach ($result in $results) {
                $result.Result | Should -Be 'NotApplicable'
                $result.Error | Should -Not -BeNullOrEmpty
                $result.Finding | Should -Match 'not established'
                $result.Finding | Should -Match 'rather than a pass'
            }
        }

        It 'Does not describe a value it never observed' {
            $results = @(& $checkFile)
            foreach ($result in $results) {
                $result.Finding | Should -Not -Match 'is Disabled'
                $result.Finding | Should -Not -Match 'is Enabled'
            }
        }
    }

    Context 'a setting is null' {
        BeforeAll {
            Mock Get-CsTeamsMessagingConfiguration {
                [PSCustomObject]@{
                    FileTypeCheck                     = $null
                    UrlReputationCheck                = 'Enabled'
                    ReportIncorrectSecurityDetections = 'Enabled'
                }
            }
        }

        It 'Treats null the same as absent' {
            (Get-Teams016Result @(& $checkFile) 'FileTypeCheck')[0].Result | Should -Be 'NotApplicable'
        }
    }

    Context 'a setting carries an unrecognized value' {
        BeforeAll {
            Mock Get-CsTeamsMessagingConfiguration {
                [PSCustomObject]@{
                    FileTypeCheck                     = 'Audit'
                    UrlReputationCheck                = 'Enabled'
                    ReportIncorrectSecurityDetections = 'Enabled'
                }
            }
        }

        It 'Returns Warning naming the unrecognized value' {
            $result = (Get-Teams016Result @(& $checkFile) 'FileTypeCheck')[0]
            $result.Result | Should -Be 'Warning'
            $result.Finding | Should -Match "'Audit'"
        }
    }

    Context 'values arrive in a different case' {
        BeforeAll {
            Mock Get-CsTeamsMessagingConfiguration {
                [PSCustomObject]@{
                    FileTypeCheck                     = 'enabled'
                    UrlReputationCheck                = 'DISABLED'
                    ReportIncorrectSecurityDetections = 'Enabled'
                }
            }
        }

        It 'Compares case-insensitively' {
            $results = @(& $checkFile)
            (Get-Teams016Result $results 'FileTypeCheck')[0].Result | Should -Be 'Pass'
            (Get-Teams016Result $results 'UrlReputationCheck')[0].Result | Should -Be 'Fail'
        }
    }

    Context 'Get-CsTeamsMessagingConfiguration throws' {
        BeforeAll {
            Mock Get-CsTeamsMessagingConfiguration { throw 'Access denied' }
        }

        It 'Returns a single Fail with the error message populated' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'High'
            $results[0].AffectedObject | Should -Be 'Teams Messaging Configuration'
            $results[0].Error | Should -Match 'Access denied'
            $results[0].Recommendation | Should -Match 'Teams administrator'
        }
    }
}
