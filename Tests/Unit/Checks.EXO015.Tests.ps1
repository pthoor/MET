BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"

    function Get-ExternalInOutlook { [CmdletBinding()] param() }
}

Describe 'MET-EXO015 External Sender Tag' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'EXO' 'MET-EXO015-ExternalSenderTag.ps1'
    }

    Context 'Enabled with empty allow list' {
        BeforeAll {
            Mock Get-ExternalInOutlook {
                [PSCustomObject]@{
                    Enabled  = $true
                    AllowList = @()
                }
            }
        }

        It 'Returns Pass' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].Finding | Should -Match 'External sender tagging is enabled'
        }
    }

    Context 'Enabled with allow list entries' {
        BeforeAll {
            Mock Get-ExternalInOutlook {
                [PSCustomObject]@{
                    Enabled  = $true
                    AllowList = @('sender1@contoso.com', 'sender2@contoso.com')
                }
            }
        }

        It 'Returns Pass and mentions allow list count' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
            $results[0].Finding | Should -Match '2 sender'
            $results[0].Finding | Should -Match 'exempted from the tag'
        }
    }

    Context 'Disabled' {
        BeforeAll {
            Mock Get-ExternalInOutlook {
                [PSCustomObject]@{
                    Enabled  = $false
                    AllowList = @()
                }
            }
        }

        It 'Returns Warning' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].Finding | Should -Match 'disabled'
        }

        It 'Recommendation mentions Set-ExternalInOutlook' {
            $results = & $checkFile
            $results[0].Recommendation | Should -Match 'Set-ExternalInOutlook -Enabled'
        }
    }

    Context 'Get-ExternalInOutlook throws' {
        BeforeAll {
            Mock Get-ExternalInOutlook { throw 'Access Denied' }
        }

        It 'Returns Fail with Error populated' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Error | Should -Not -BeNullOrEmpty
            $results[0].Error | Should -Match 'Access Denied'
        }

        It 'Recommendation references the known ErrorAction bug and documented permissions' {
            $results = & $checkFile
            $results[0].Recommendation | Should -Match 'ExchangeOnlineManagement bug'
            $results[0].Recommendation | Should -Match 'View-Only Organization Management'
        }
    }

    Context 'The configuration omits the Enabled property' {
        BeforeAll {
            Mock Get-ExternalInOutlook {
                [PSCustomObject]@{ Identity = 'Default'; AllowList = @() }
            }
        }

        It 'Does not return Pass on a setting it never observed' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Not -Be 'Pass'
            $results[0].AffectedObject | Should -Be 'External Sender Tag Configuration'
        }

        It 'States the property was not returned rather than that tagging is disabled' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'was not returned'
            $results[0].Finding | Should -Not -Match 'External sender tagging is disabled'
        }
    }

    Context 'Get-ExternalInOutlook returns $null' {
        BeforeAll {
            Mock Get-ExternalInOutlook { $null }
        }

        It 'Does not return Pass, and states the configuration was not returned' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'was not returned'
        }
    }

    # Mutation verification: the absent-property path and the present-and-false path must
    # both stay Warning, with different Findings.
    Context 'Enabled absent vs. present and false' {
        It 'Produces different Findings for the same Warning verdict' {
            Mock Get-ExternalInOutlook { [PSCustomObject]@{ Identity = 'Default'; AllowList = @() } }
            $absent = (& $checkFile)[0]
            $absent.Result | Should -Be 'Warning'
            $absent.Finding | Should -Match 'was not returned'
            $absent.Finding | Should -Not -Match 'External sender tagging is disabled'

            Mock Get-ExternalInOutlook { [PSCustomObject]@{ Enabled = $false; AllowList = @() } }
            $present = (& $checkFile)[0]
            $present.Result | Should -Be 'Warning'
            $present.Finding | Should -Match 'External sender tagging is disabled'
            $present.Finding | Should -Not -Match 'was not returned'
        }
    }
}
