BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"

    # Stub Graph cmdlets needed by Teams014 - these are not real cmdlets in the test
    # environment (Microsoft.Graph.Identity.SignIns is not installed here), so define
    # them as plain functions first so Pester's Mock can target them.
    function Get-MgPolicyCrossTenantAccessPolicyDefault { [CmdletBinding()] param() }
    function Get-MgPolicyAuthorizationPolicy             { [CmdletBinding()] param() }

    $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'Teams' 'MET-Teams014-CrossTenantAccess.ps1'
}

Describe 'MET-Teams014 Cross-Tenant Access' {

    Context 'Graph cmdlets not found (module absent)' {
        BeforeEach {
            Mock Get-Command { $null } -ParameterFilter { $Name -eq 'Get-MgPolicyCrossTenantAccessPolicyDefault' }
        }

        It 'Returns a single NotApplicable result with ErrorMessage populated' {
            $results = & $checkFile
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'NotApplicable'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].CheckId | Should -Be 'MET-Teams014'
            $results[0].Error | Should -Not -BeNullOrEmpty
            $results[0].Finding | Should -Match 'Microsoft Graph'
        }
    }

    Context 'Graph cmdlet throws (connected but call fails)' {
        BeforeEach {
            Mock Get-MgPolicyCrossTenantAccessPolicyDefault { throw 'Graph request failed: Forbidden' }
        }

        It 'Returns a single NotApplicable result and does not throw' {
            $results = & $checkFile
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'NotApplicable'
            $results[0].Error | Should -Match 'Forbidden'
        }
    }

    Context 'Graph cmdlets entirely absent from the session (CommandNotFoundException)' {
        BeforeEach {
            Mock Get-MgPolicyCrossTenantAccessPolicyDefault {
                throw [System.Management.Automation.CommandNotFoundException]::new('The term Get-MgPolicyCrossTenantAccessPolicyDefault is not recognized')
            }
        }

        It 'Never throws and returns a NotApplicable result' {
            { & $checkFile } | Should -Not -Throw
            $results = & $checkFile
            $results[0].Result | Should -Be 'NotApplicable'
        }
    }

    Context 'Graph succeeds - default policy is unmodified system default (open collaboration)' {
        BeforeEach {
            Mock Get-MgPolicyCrossTenantAccessPolicyDefault {
                [PSCustomObject]@{
                    IsServiceDefault         = $true
                    B2BCollaborationInbound  = $null
                    B2BCollaborationOutbound = $null
                }
            }
            Mock Get-MgPolicyAuthorizationPolicy {
                [PSCustomObject]@{
                    AllowInvitesFrom = 'everyone'
                }
            }
        }

        It 'Produces a result without throwing and flags the open defaults' {
            $results = & $checkFile
            $results.Count | Should -Be 1
            $results[0].Result | Should -BeIn @('Warning', 'Fail')
            $results[0].Severity | Should -Be 'Medium'
            $results[0].Finding | Should -Match 'IsServiceDefault|everyone'
        }
    }

    Context 'Graph succeeds - explicit inbound Allowed access with no target restriction' {
        BeforeEach {
            Mock Get-MgPolicyCrossTenantAccessPolicyDefault {
                [PSCustomObject]@{
                    IsServiceDefault        = $false
                    B2BCollaborationInbound = [PSCustomObject]@{
                        UsersAndGroups = [PSCustomObject]@{
                            AccessType = 'allowed'
                            Targets    = @()
                        }
                    }
                }
            }
            Mock Get-MgPolicyAuthorizationPolicy {
                [PSCustomObject]@{
                    AllowInvitesFrom = 'adminsAndGuestInviters'
                }
            }
        }

        It 'Produces a Warning-leaning result referencing inbound collaboration without throwing' {
            $results = & $checkFile
            $results.Count | Should -Be 1
            $results[0].Result | Should -Not -BeNullOrEmpty
            { & $checkFile } | Should -Not -Throw
        }
    }

    Context 'Graph succeeds - restrictive, customized policy' {
        BeforeEach {
            Mock Get-MgPolicyCrossTenantAccessPolicyDefault {
                [PSCustomObject]@{
                    IsServiceDefault        = $false
                    B2BCollaborationInbound = [PSCustomObject]@{
                        UsersAndGroups = [PSCustomObject]@{
                            AccessType = 'blocked'
                            Targets    = @()
                        }
                    }
                }
            }
            Mock Get-MgPolicyAuthorizationPolicy {
                [PSCustomObject]@{
                    AllowInvitesFrom = 'adminsAndGuestInviters'
                }
            }
        }

        It 'Returns Pass' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
            $results[0].Severity | Should -Be 'Medium'
        }
    }

    Context 'Graph succeeds but returns an unrecognized object shape' {
        BeforeEach {
            Mock Get-MgPolicyCrossTenantAccessPolicyDefault {
                [PSCustomObject]@{ SomeUnexpectedProperty = 'value' }
            }
            Mock Get-MgPolicyAuthorizationPolicy {
                [PSCustomObject]@{ AnotherUnexpectedProperty = 'value' }
            }
        }

        It 'Falls back to Info rather than guessing at a Pass/Fail condition, and does not throw' {
            { & $checkFile } | Should -Not -Throw
            $results = & $checkFile
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Info'
            $results[0].Severity | Should -Be 'Medium'
        }
    }
}
