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

        It 'States RejectDirectSend was not returned rather than asserting it is disabled' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Fail'
            $results[0].Finding | Should -Match 'RejectDirectSend was not returned'
            $results[0].Finding | Should -Not -Match 'RejectDirectSend is disabled'
        }

        It 'Justifies the Fail with the platform default rather than a version-history aside' {
            $results = @(& $checkFile)
            $results[0].Finding | Should -Match 'platform default for Direct Send is not blocked'
            $results[0].Finding | Should -Not -Match 'not a hypothetical'
        }
    }

    # Mutation verification: the absent path and the present-and-false path must both
    # fail closed, with different Findings.
    Context 'RejectDirectSend absent vs. present and false' {
        It 'Produces different Findings for the same Fail verdict' {
            Mock Get-OrganizationConfig { [PSCustomObject]@{ Name = 'contoso.onmicrosoft.com' } }
            $absent = (& $checkFile)[0]
            $absent.Result | Should -Be 'Fail'
            $absent.Finding | Should -Match 'RejectDirectSend was not returned'
            $absent.Finding | Should -Not -Match 'RejectDirectSend is disabled'

            Mock Get-OrganizationConfig { [PSCustomObject]@{ RejectDirectSend = $false } }
            $present = (& $checkFile)[0]
            $present.Result | Should -Be 'Fail'
            $present.Finding | Should -Match 'RejectDirectSend is disabled'
            $present.Finding | Should -Not -Match 'RejectDirectSend was not returned'
        }
    }

    # RejectDirectSend $true is the hardened state: Direct Send is rejected. A refactor
    # that reads the property as "Direct Send is allowed" inverts the verdict silently,
    # so both senses are pinned here rather than only the one the other contexts happen
    # to exercise.
    Context 'Inverted-sense regression guard' {
        It 'Passes only when RejectDirectSend is true and fails only when it is false' {
            Mock Get-OrganizationConfig { [PSCustomObject]@{ RejectDirectSend = $true } }
            (& $checkFile)[0].Result | Should -Be 'Pass'

            Mock Get-OrganizationConfig { [PSCustomObject]@{ RejectDirectSend = $false } }
            (& $checkFile)[0].Result | Should -Be 'Fail'
        }

        It 'Names the blocked state only in the Pass and the unblocked state only in the Fail' {
            Mock Get-OrganizationConfig { [PSCustomObject]@{ RejectDirectSend = $true } }
            $secure = (& $checkFile)[0]
            $secure.Finding | Should -Match 'Direct Send is blocked'
            $secure.Finding | Should -Not -Match 'RejectDirectSend is disabled'

            Mock Get-OrganizationConfig { [PSCustomObject]@{ RejectDirectSend = $false } }
            $insecure = (& $checkFile)[0]
            $insecure.Finding | Should -Match 'Direct Send is not blocked'
            $insecure.Finding | Should -Match 'RejectDirectSend is disabled'
        }
    }
}
