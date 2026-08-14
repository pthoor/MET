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
    }
}
