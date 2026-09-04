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

    Context 'The RejectDirectSend property is absent from the organization configuration' {
        BeforeAll {
            Mock Get-OrganizationConfig {
                [PSCustomObject]@{ Name = 'contoso.onmicrosoft.com' }
            }
        }

        It 'Does not return Pass on a setting it never observed' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Not -Be 'Pass'
            $results[0].AffectedObject | Should -Be 'Organization Configuration'
        }

        # Pins current behaviour, whose wording is wrong: the check states RejectDirectSend
        # is disabled, quoting a property the organization configuration never returned.
        # The verdict is fail-closed and safe, but the sentence states an observation that
        # was not made. Left pinned rather than corrected here so the defect is visible and
        # cannot change unnoticed.
        It 'Currently states RejectDirectSend is disabled rather than that it was not returned' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Fail'
            $results[0].Finding | Should -Match 'RejectDirectSend is disabled'
            $results[0].Finding | Should -Not -Match 'not returned'
        }
    }
}
