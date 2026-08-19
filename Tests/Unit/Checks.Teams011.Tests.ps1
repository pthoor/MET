BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"

    # Stub Teams cmdlets needed by Teams011
    function Get-CsTenantFederationConfiguration { [CmdletBinding()] param() }
    function Get-CsTeamsExternalAccessConfiguration { [CmdletBinding()] param() }
}

Describe 'MET-Teams011 SecOps Blocklist Authority' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'Teams' 'MET-Teams011-SecOpsBlocklistAuthority.ps1'
    }

    Context 'delegation enabled' {
        BeforeAll {
            Mock Get-CsTenantFederationConfiguration {
                [PSCustomObject]@{
                    SecurityTeamAllowBlockListDelegation = 'Enabled'
                }
            }
            Mock Get-CsTeamsExternalAccessConfiguration {
                [PSCustomObject]@{
                    BlockedUsers = @()
                }
            }
        }
        It 'Returns Pass' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
            $results[0].Severity | Should -Be 'Medium'
        }
    }

    Context 'delegation disabled' {
        BeforeAll {
            Mock Get-CsTenantFederationConfiguration {
                [PSCustomObject]@{
                    SecurityTeamAllowBlockListDelegation = 'Disabled'
                }
            }
            Mock Get-CsTeamsExternalAccessConfiguration {
                [PSCustomObject]@{
                    BlockedUsers = @()
                }
            }
        }
        It 'Returns Warning and Finding mentions cannot block' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'cannot block'
        }
    }

    Context 'BlockedUsers populated' {
        BeforeAll {
            Mock Get-CsTenantFederationConfiguration {
                [PSCustomObject]@{
                    SecurityTeamAllowBlockListDelegation = 'Enabled'
                }
            }
            Mock Get-CsTeamsExternalAccessConfiguration {
                [PSCustomObject]@{
                    BlockedUsers = @('baduser1@contoso.com', 'baduser2@contoso.com')
                }
            }
        }
        It 'Returns Pass (unchanged by populated blocklist) and Finding mentions blocked count' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
            $results[0].Finding | Should -Match '2 user\(s\) currently blocked'
        }
    }

    Context 'BlockedUsers empty' {
        BeforeAll {
            Mock Get-CsTenantFederationConfiguration {
                [PSCustomObject]@{
                    SecurityTeamAllowBlockListDelegation = 'Enabled'
                }
            }
            Mock Get-CsTeamsExternalAccessConfiguration {
                [PSCustomObject]@{
                    BlockedUsers = @()
                }
            }
        }
        It 'Returns Pass (unchanged by empty blocklist) and Finding notes no users blocked' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
            $results[0].Finding | Should -Match 'No users currently blocked'
        }
    }

    Context 'BlockedUsers property absent' {
        BeforeAll {
            Mock Get-CsTenantFederationConfiguration {
                [PSCustomObject]@{
                    SecurityTeamAllowBlockListDelegation = 'Enabled'
                }
            }
            Mock Get-CsTeamsExternalAccessConfiguration {
                [PSCustomObject]@{}
            }
        }
        It 'Does not throw and treats missing property as no users blocked' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
            $results[0].Finding | Should -Match 'No users currently blocked'
        }
    }

    Context 'federation configuration cmdlet throws, external access configuration succeeds' {
        BeforeAll {
            Mock Get-CsTenantFederationConfiguration { throw 'Access denied' }
            Mock Get-CsTeamsExternalAccessConfiguration {
                [PSCustomObject]@{
                    BlockedUsers = @('baduser1@contoso.com')
                }
            }
        }
        It 'Returns Warning (not a hard Error) and Finding still surfaces blocked user data' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match '1 user\(s\) currently blocked'
            $results[0].Error | Should -BeNullOrEmpty
        }
    }

    Context 'external access configuration cmdlet throws, federation configuration succeeds' {
        BeforeAll {
            Mock Get-CsTenantFederationConfiguration {
                [PSCustomObject]@{
                    SecurityTeamAllowBlockListDelegation = 'Enabled'
                }
            }
            Mock Get-CsTeamsExternalAccessConfiguration { throw 'Access denied' }
        }
        It 'Returns Pass and Finding notes blocked list could not be retrieved' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
            $results[0].Finding | Should -Match 'Could not retrieve current Teams external access blocked users list'
            $results[0].Error | Should -BeNullOrEmpty
        }
    }

    Context 'both cmdlets throw' {
        BeforeAll {
            Mock Get-CsTenantFederationConfiguration { throw 'Federation config unavailable' }
            Mock Get-CsTeamsExternalAccessConfiguration { throw 'External access config unavailable' }
        }
        It 'Returns Fail with ErrorMessage combining both exceptions' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Error | Should -Match 'Federation config unavailable'
            $results[0].Error | Should -Match 'External access config unavailable'
        }
    }
}
