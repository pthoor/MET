BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"

    # Stub Teams cmdlet needed by Teams006
    function Get-CsTenantFederationConfiguration { [CmdletBinding()] param() }
}

Describe 'MET-Teams006 External Access' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'Teams' 'MET-Teams006-ExternalAccess.ps1'
    }

    Context 'federation restricted to specific domains, consumer disabled' {
        BeforeAll {
            Mock Get-CsTenantFederationConfiguration {
                [PSCustomObject]@{
                    AllowFederatedUsers = $true
                    AllowedDomains      = 'SomeScopedDomainsObject'
                    AllowTeamsConsumer  = $false
                    BlockedDomains      = @()
                    AllowPublicUsers    = $false
                }
            }
        }
        It 'Returns Pass' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
        }
    }

    Context 'open federation (AllowAllKnownDomains)' {
        BeforeAll {
            Mock Get-CsTenantFederationConfiguration {
                [PSCustomObject]@{
                    AllowFederatedUsers = $true
                    AllowedDomains      = 'AllowAllKnownDomains'
                    AllowTeamsConsumer  = $false
                    BlockedDomains      = @()
                    AllowPublicUsers    = $false
                }
            }
        }
        It 'Returns Fail and Finding mentions AllowAllKnownDomains' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Finding | Should -Match 'AllowAllKnownDomains'
        }
    }

    Context 'Teams consumer access allowed' {
        BeforeAll {
            Mock Get-CsTenantFederationConfiguration {
                [PSCustomObject]@{
                    AllowFederatedUsers = $true
                    AllowedDomains      = 'SomeScopedDomainsObject'
                    AllowTeamsConsumer  = $true
                    BlockedDomains      = @()
                    AllowPublicUsers    = $false
                }
            }
        }
        It 'Returns Warning (not Fail, since only the consumer flag triggered)' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'consumer'
        }
    }

    Context 'cmdlet throws (module absent)' {
        BeforeAll {
            Mock Get-CsTenantFederationConfiguration { throw 'Teams federation configuration unavailable' }
        }
        It 'Returns Warning and Finding mentions Could not retrieve' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'Could not retrieve'
        }
    }
}
