BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"

    function Get-CsTeamsClientConfiguration { [CmdletBinding()] param() }
}

Describe 'MET-Teams015 Teams Email Integration' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'Teams' 'MET-Teams015-EmailIntegration.ps1'
    }

    Context 'AllowEmailIntoChannel is false' {
        BeforeAll {
            Mock Get-CsTeamsClientConfiguration {
                [PSCustomObject]@{ Identity = 'Global'; AllowEmailIntoChannel = $false }
            }
        }

        It 'Returns Pass' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Pass'
            $results[0].CheckId | Should -Be 'MET-Teams015'
            $results[0].Category | Should -Be 'Teams'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].AffectedObject | Should -Be 'Teams Client Configuration'
            $results[0].Finding | Should -Match 'disabled'
        }
    }

    Context 'AllowEmailIntoChannel is true' {
        BeforeAll {
            Mock Get-CsTeamsClientConfiguration {
                [PSCustomObject]@{ Identity = 'Global'; AllowEmailIntoChannel = $true }
            }
        }

        It 'Returns Warning describing the unmonitored ingress path' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Warning'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].Finding | Should -Match 'AllowEmailIntoChannel is set to true'
            $results[0].Recommendation | Should -Match 'Set-CsTeamsClientConfiguration'
        }
    }

    Context 'AllowEmailIntoChannel is null' {
        BeforeAll {
            Mock Get-CsTeamsClientConfiguration {
                [PSCustomObject]@{ Identity = 'Global'; AllowEmailIntoChannel = $null }
            }
        }

        It 'Returns Warning stating the setting could not be confirmed' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Warning'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].Finding | Should -Match 'could not be confirmed'
        }
    }

    Context 'AllowEmailIntoChannel property is absent' {
        BeforeAll {
            Mock Get-CsTeamsClientConfiguration {
                [PSCustomObject]@{ Identity = 'Global' }
            }
        }

        It 'Returns Warning rather than silently passing' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'was absent'
        }
    }

    Context 'Get-CsTeamsClientConfiguration throws' {
        BeforeAll {
            Mock Get-CsTeamsClientConfiguration {
                throw 'Access denied'
            }
        }

        It 'Returns Fail with the error message populated' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].AffectedObject | Should -Be 'Teams Client Configuration'
            $results[0].Error | Should -Not -BeNullOrEmpty
            $results[0].Error | Should -Match 'Access denied'
            $results[0].Recommendation | Should -Match 'Teams administrator'
        }
    }

    # AllowEmailIntoChannel $true is the permissive state, so the secure verdict is the
    # one attached to $false - the opposite pairing to most Allow* settings the suite
    # asserts. A refactor that reads the property as a protection toggle inverts it.
    Context 'Inverted-sense regression guard' {
        It 'Warns only when AllowEmailIntoChannel is true and passes only when it is false' {
            Mock Get-CsTeamsClientConfiguration {
                [PSCustomObject]@{ Identity = 'Global'; AllowEmailIntoChannel = $true }
            }
            (& $checkFile)[0].Result | Should -Be 'Warning'

            Mock Get-CsTeamsClientConfiguration {
                [PSCustomObject]@{ Identity = 'Global'; AllowEmailIntoChannel = $false }
            }
            (& $checkFile)[0].Result | Should -Be 'Pass'
        }

        It 'Names the enabled ingress path only in the Warning and the closed one only in the Pass' {
            Mock Get-CsTeamsClientConfiguration {
                [PSCustomObject]@{ Identity = 'Global'; AllowEmailIntoChannel = $true }
            }
            $insecure = (& $checkFile)[0]
            $insecure.Finding | Should -Match 'Channel email integration is enabled'
            $insecure.Finding | Should -Not -Match 'Channel email integration is disabled'

            Mock Get-CsTeamsClientConfiguration {
                [PSCustomObject]@{ Identity = 'Global'; AllowEmailIntoChannel = $false }
            }
            $secure = (& $checkFile)[0]
            $secure.Finding | Should -Match 'Channel email integration is disabled'
            $secure.Finding | Should -Not -Match 'Channel email integration is enabled'
        }
    }
}
