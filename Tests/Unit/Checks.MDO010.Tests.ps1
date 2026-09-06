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

        It 'Reports the toggle as unestablished rather than disabled, since the property was never returned' {
            $results = @(& $checkFile)
            $toggle = $results | Where-Object Name -eq 'Priority Account Protection Toggle'
            $toggle.Result   | Should -Be 'NotApplicable'
            $toggle.Severity | Should -Be 'High'
            $toggle.AffectedObject | Should -Be 'Contoso EmailTenantSettings'
            $toggle.Finding  | Should -Not -Match 'is disabled'
            $toggle.Finding  | Should -Match 'not established'
            $toggle.Error    | Should -Match 'EnablePriorityAccountProtection'
        }

        It 'Still assesses tagging as its own independent result' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 2
            ($results | Where-Object Name -eq 'Priority Account Tagging').Result | Should -Be 'Pass'
        }
    }

    Context 'EmailTenantSettings returns EnablePriorityAccountProtection as an explicit $null' {
        BeforeEach {
            Mock Get-EmailTenantSettings {
                [PSCustomObject]@{ Identity = 'Contoso EmailTenantSettings'; EnablePriorityAccountProtection = $null }
            }
        }

        It 'Treats a present-but-null value the same as an absent property' {
            $results = @(& $checkFile)
            $toggle = $results | Where-Object Name -eq 'Priority Account Protection Toggle'
            $toggle.Result   | Should -Be 'NotApplicable'
            $toggle.Severity | Should -Be 'High'
            $toggle.Finding  | Should -Not -Match 'is disabled'
            $toggle.Finding  | Should -Match 'not established'
        }
    }

    Context 'Get-EmailTenantSettings returns nothing without throwing' {
        BeforeEach {
            Mock Get-EmailTenantSettings { }
        }

        It 'No longer emits zero results for the toggle - a result now exists naming the unassessed control' {
            $results = @(& $checkFile)
            $toggleResults = @($results | Where-Object Name -eq 'Priority Account Protection Toggle')
            $toggleResults.Count | Should -Be 1
        }

        It 'Reports the toggle as NotApplicable with the retrieval failure recorded in Error' {
            $results = @(& $checkFile)
            $toggle = $results | Where-Object Name -eq 'Priority Account Protection Toggle'
            $toggle.Result   | Should -Be 'NotApplicable'
            $toggle.Severity | Should -Be 'High'
            $toggle.AffectedObject | Should -Be 'EmailTenantSettings'
            $toggle.Finding  | Should -Match 'not established'
            $toggle.Error    | Should -Match 'Get-EmailTenantSettings returned no object'
        }

        It 'Still assesses tagging alongside the toggle result, so the fix does not swallow the second half' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 2
            ($results | Where-Object Name -eq 'Priority Account Tagging').Result | Should -Be 'Pass'
        }
    }

    Context '$tenantSettings arrives as an array rather than a scalar object' {
        BeforeEach {
            Mock Get-EmailTenantSettings {
                @([PSCustomObject]@{ Identity = 'Contoso EmailTenantSettings'; EnablePriorityAccountProtection = $true })
            }
        }

        It 'Assesses the first object rather than throwing' {
            $results = @(& $checkFile)
            $toggle = $results | Where-Object Name -eq 'Priority Account Protection Toggle'
            $toggle.Result | Should -Be 'Pass'
            $toggle.AffectedObject | Should -Be 'Contoso EmailTenantSettings'
        }
    }
}
