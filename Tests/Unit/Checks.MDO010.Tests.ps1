BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"

    function Get-EmailTenantSettings { [CmdletBinding()] param() }
    function Get-User { [CmdletBinding()] param([switch]$IsVIP, [string]$ResultSize) }

    $checkFile = Join-Path $root 'Checks' 'MDO' 'MET-MDO010-PriorityAccounts.ps1'
}

Describe 'MET-MDO010 Priority Accounts' {
    BeforeEach {
        Mock Get-User { @([PSCustomObject]@{ Name = 'ceo'; UserPrincipalName = 'ceo@contoso.com' }) }
    }

    Context 'Priority account protection is enabled and accounts are tagged' {
        BeforeEach {
            Mock Get-EmailTenantSettings {
                [PSCustomObject]@{ Identity = 'Contoso EmailTenantSettings'; EnablePriorityAccountProtection = $true }
            }
        }

        It 'Passes the tenant toggle, naming the settings object assessed' {
            $results = @(& $checkFile)
            $toggle = $results | Where-Object Name -eq 'Priority Account Protection Toggle'
            $toggle | Should -Not -BeNullOrEmpty
            $toggle.CheckId  | Should -Be 'MET-MDO010'
            $toggle.Category | Should -Be 'MDO'
            $toggle.Result   | Should -Be 'Pass'
            $toggle.Severity | Should -Be 'High'
            $toggle.AffectedObject | Should -Be 'Contoso EmailTenantSettings'
            $toggle.Finding  | Should -Match 'Priority account protection is enabled'
            $toggle.Error    | Should -BeNullOrEmpty
        }

        It 'Passes the tagging assessment with the tagged-user count' {
            $results = @(& $checkFile)
            $tagging = $results | Where-Object Name -eq 'Priority Account Tagging'
            $tagging.Result   | Should -Be 'Pass'
            $tagging.Severity | Should -Be 'Medium'
            $tagging.AffectedObject | Should -Be 'Priority Account Tags (1 tagged)'
            $tagging.Finding  | Should -Be '1 user has the Priority Account tag applied'
        }

        It 'Pluralises the tagged-user count for more than one user' {
            Mock Get-User {
                @(
                    [PSCustomObject]@{ Name = 'ceo' }
                    [PSCustomObject]@{ Name = 'cfo' }
                    [PSCustomObject]@{ Name = 'ciso' }
                )
            }
            $results = @(& $checkFile)
            $tagging = $results | Where-Object Name -eq 'Priority Account Tagging'
            $tagging.Result | Should -Be 'Pass'
            $tagging.AffectedObject | Should -Be 'Priority Account Tags (3 tagged)'
            $tagging.Finding | Should -Be '3 users have the Priority Account tag applied'
        }
    }

    Context 'Priority account protection is disabled' {
        BeforeEach {
            Mock Get-EmailTenantSettings {
                [PSCustomObject]@{ Identity = 'Contoso EmailTenantSettings'; EnablePriorityAccountProtection = $false }
            }
        }

        It 'Fails the toggle at High severity naming the silent loss of protection' {
            $results = @(& $checkFile)
            $toggle = $results | Where-Object Name -eq 'Priority Account Protection Toggle'
            $toggle.Result   | Should -Be 'Fail'
            $toggle.Severity | Should -Be 'High'
            $toggle.AffectedObject | Should -Be 'Contoso EmailTenantSettings'
            $toggle.Finding  | Should -Match 'Priority account protection is disabled'
            $toggle.Recommendation | Should -Match 'security\.microsoft\.com/securitysettings/priorityAccountProtection'
        }

        It 'Still assesses tagging, since the two are independent controls' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 2
            ($results | Where-Object Name -eq 'Priority Account Tagging').Result | Should -Be 'Pass'
        }
    }

    Context 'No user carries the Priority Account tag' {
        BeforeEach {
            Mock Get-EmailTenantSettings {
                [PSCustomObject]@{ Identity = 'Contoso EmailTenantSettings'; EnablePriorityAccountProtection = $true }
            }
            Mock Get-User { @() }
        }

        It 'Warns at Medium severity rather than passing on an unused control' {
            $results = @(& $checkFile)
            $tagging = $results | Where-Object Name -eq 'Priority Account Tagging'
            $tagging.Result   | Should -Be 'Warning'
            $tagging.Severity | Should -Be 'Medium'
            $tagging.AffectedObject | Should -Be 'Priority Account Tags'
            $tagging.Finding  | Should -Match 'No users have the Priority Account tag applied'
        }
    }

    Context 'Get-EmailTenantSettings throws' {
        BeforeEach {
            Mock Get-EmailTenantSettings { throw 'The term Get-EmailTenantSettings is not recognized.' }
        }

        It 'Fails once and carries the exception text in Error rather than the Finding' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result   | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'High'
            $results[0].AffectedObject | Should -Be 'EmailTenantSettings'
            $results[0].Finding | Should -Match 'Unable to retrieve EmailTenantSettings'
            $results[0].Error   | Should -Match 'Get-EmailTenantSettings is not recognized'
            $results[0].Finding | Should -Not -Match 'is not recognized'
        }

        It 'Stops before the tagging assessment rather than reporting a partial pass' {
            $results = @(& $checkFile)
            ($results | Where-Object Name -eq 'Priority Account Tagging') | Should -BeNullOrEmpty
        }
    }

    Context 'Get-User throws' {
        BeforeEach {
            Mock Get-EmailTenantSettings {
                [PSCustomObject]@{ Identity = 'Contoso EmailTenantSettings'; EnablePriorityAccountProtection = $true }
            }
            Mock Get-User { throw 'Insufficient access rights to perform the operation.' }
        }

        It 'Fails the tagging half at Medium severity with the exception in Error' {
            $results = @(& $checkFile)
            $tagging = $results | Where-Object Name -eq 'Priority Account Tagging'
            $tagging.Result   | Should -Be 'Fail'
            $tagging.Severity | Should -Be 'Medium'
            $tagging.AffectedObject | Should -Be 'Priority Account Tags'
            $tagging.Finding | Should -Match 'Unable to retrieve Priority Account tag membership'
            $tagging.Error   | Should -Match 'Insufficient access rights'
        }

        It 'Keeps the toggle result it had already established' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 2
            ($results | Where-Object Name -eq 'Priority Account Protection Toggle').Result | Should -Be 'Pass'
        }
    }

    Context 'EmailTenantSettings omits EnablePriorityAccountProtection' {
        BeforeEach {
            Mock Get-EmailTenantSettings {
                [PSCustomObject]@{ Identity = 'Contoso EmailTenantSettings' }
            }
        }

        It 'Does not return Pass for a toggle state that was never observed' {
            $results = @(& $checkFile)
            $toggle = $results | Where-Object Name -eq 'Priority Account Protection Toggle'
            $toggle.Result | Should -Not -Be 'Pass'
        }

        # Pins current behaviour. Fail is the safe direction, but the Finding asserts
        # the toggle "is disabled" for a value the service never returned.
        It 'Currently states the toggle is disabled rather than unestablished' {
            $results = @(& $checkFile)
            $toggle = $results | Where-Object Name -eq 'Priority Account Protection Toggle'
            $toggle.Result   | Should -Be 'Fail'
            $toggle.Severity | Should -Be 'High'
            $toggle.Finding  | Should -Match 'Priority account protection is disabled'
        }
    }

    Context 'Get-EmailTenantSettings returns nothing without throwing' {
        BeforeEach {
            Mock Get-EmailTenantSettings { }
        }

        # Pins current behaviour, which is wrong: the toggle half emits no result at
        # all, so MDO010 reports only the tagging Pass and nothing in the report says
        # the tenant toggle went unassessed. Under the default aggregation the check
        # collapses to a clean Pass.
        It 'Currently emits no result for the toggle, leaving only the tagging result' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Name   | Should -Be 'Priority Account Tagging'
            $results[0].Result | Should -Be 'Pass'
            ($results | Where-Object Name -eq 'Priority Account Protection Toggle') | Should -BeNullOrEmpty
        }
    }
}
