BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"

    function Get-OrganizationConfig { [CmdletBinding()] param() }
}

Describe 'MET-EXO010 Direct Send' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'EXO' 'MET-EXO010-DirectSend.ps1'
    }

    Context 'RejectDirectSend is true' {
        BeforeAll {
            Mock Get-OrganizationConfig {
                [PSCustomObject]@{ RejectDirectSend = $true }
            }
        }

        It 'Returns Pass' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
            $results[0].Severity | Should -Be 'Critical'
            $results[0].CheckId | Should -Be 'MET-EXO010'
        }
    }

    Context 'RejectDirectSend is false' {
        BeforeAll {
            Mock Get-OrganizationConfig {
                [PSCustomObject]@{ RejectDirectSend = $false }
            }
        }

        It 'Returns Fail with Critical severity' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'Critical'
            $results[0].Finding | Should -Match 'RejectDirectSend is disabled'
        }
    }

    Context 'RejectDirectSend is null' {
        BeforeAll {
            Mock Get-OrganizationConfig {
                [PSCustomObject]@{ RejectDirectSend = $null }
            }
        }

        It 'Returns Fail' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'Critical'
        }
    }

    Context 'Get-OrganizationConfig throws' {
        BeforeAll {
            Mock Get-OrganizationConfig {
                throw 'Access denied'
            }
        }

        It 'Returns Fail with error message populated' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'Critical'
            $results[0].Error | Should -Not -BeNullOrEmpty
            $results[0].Error | Should -Match 'Access denied'
        }
    }
}
