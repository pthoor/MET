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
                    AllowFederatedUsers                        = $true
                    AllowedDomains                              = 'SomeScopedDomainsObject'
                    AllowTeamsConsumer                          = $false
                    AllowTeamsConsumerInbound                   = $false
                    RestrictTeamsConsumerToExternalUserProfiles = $false
                    BlockedDomains                              = @('malicious.com')
                    AllowPublicUsers                            = $false
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
                    AllowFederatedUsers                        = $true
                    AllowedDomains                              = 'AllowAllKnownDomains'
                    AllowTeamsConsumer                          = $false
                    AllowTeamsConsumerInbound                   = $false
                    RestrictTeamsConsumerToExternalUserProfiles = $false
                    BlockedDomains                              = @('malicious.com')
                    AllowPublicUsers                            = $false
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
                    AllowFederatedUsers                        = $true
                    AllowedDomains                              = 'SomeScopedDomainsObject'
                    AllowTeamsConsumer                          = $true
                    AllowTeamsConsumerInbound                   = $true
                    RestrictTeamsConsumerToExternalUserProfiles = $false
                    BlockedDomains                              = @('malicious.com')
                    AllowPublicUsers                            = $false
                }
            }
        }
        It 'Returns Warning (not Fail, since only the consumer flag triggered)' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'consumer'
        }
    }

    Context 'consumer allowed with inbound also allowed (worse case)' {
        BeforeAll {
            Mock Get-CsTenantFederationConfiguration {
                [PSCustomObject]@{
                    AllowFederatedUsers                        = $true
                    AllowedDomains                              = 'SomeScopedDomainsObject'
                    AllowTeamsConsumer                          = $true
                    AllowTeamsConsumerInbound                   = $true
                    RestrictTeamsConsumerToExternalUserProfiles = $false
                    BlockedDomains                              = @('malicious.com')
                    AllowPublicUsers                            = $false
                }
            }
        }
        It 'Returns Warning and Finding calls out that inbound contact is possible' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'AllowTeamsConsumerInbound is enabled'
            $results[0].Finding | Should -Match 'initiate first contact'
        }
    }

    Context 'consumer allowed with inbound blocked (mitigated case)' {
        BeforeAll {
            Mock Get-CsTenantFederationConfiguration {
                [PSCustomObject]@{
                    AllowFederatedUsers                        = $true
                    AllowedDomains                              = 'SomeScopedDomainsObject'
                    AllowTeamsConsumer                          = $true
                    AllowTeamsConsumerInbound                   = $false
                    RestrictTeamsConsumerToExternalUserProfiles = $false
                    BlockedDomains                              = @('malicious.com')
                    AllowPublicUsers                            = $false
                }
            }
        }
        It 'Returns Warning and Finding notes the mitigation' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'AllowTeamsConsumerInbound is disabled'
            $results[0].Finding | Should -Match 'partially mitigated'
        }
    }

    Context 'consumer allowed with RestrictTeamsConsumerToExternalUserProfiles enabled' {
        BeforeAll {
            Mock Get-CsTenantFederationConfiguration {
                [PSCustomObject]@{
                    AllowFederatedUsers                        = $true
                    AllowedDomains                              = 'SomeScopedDomainsObject'
                    AllowTeamsConsumer                          = $true
                    AllowTeamsConsumerInbound                   = $true
                    RestrictTeamsConsumerToExternalUserProfiles = $true
                    BlockedDomains                              = @('malicious.com')
                    AllowPublicUsers                            = $false
                }
            }
        }
        It 'Returns Warning and Finding notes the external user profile restriction' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'RestrictTeamsConsumerToExternalUserProfiles is enabled'
        }
    }

    Context 'BlockedDomains empty with federation enabled' {
        BeforeAll {
            Mock Get-CsTenantFederationConfiguration {
                [PSCustomObject]@{
                    AllowFederatedUsers                        = $true
                    AllowedDomains                              = 'SomeScopedDomainsObject'
                    AllowTeamsConsumer                          = $false
                    AllowTeamsConsumerInbound                   = $false
                    RestrictTeamsConsumerToExternalUserProfiles = $false
                    BlockedDomains                              = @()
                    AllowPublicUsers                            = $false
                }
            }
        }
        It 'Returns Warning and Finding mentions no BlockedDomains deny-list' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'No explicit BlockedDomains deny-list'
        }
    }

    Context 'BlockedDomains populated with federation enabled' {
        BeforeAll {
            Mock Get-CsTenantFederationConfiguration {
                [PSCustomObject]@{
                    AllowFederatedUsers                        = $true
                    AllowedDomains                              = 'SomeScopedDomainsObject'
                    AllowTeamsConsumer                          = $false
                    AllowTeamsConsumerInbound                   = $false
                    RestrictTeamsConsumerToExternalUserProfiles = $false
                    BlockedDomains                              = @('malicious.com', 'evil.example')
                    AllowPublicUsers                            = $false
                }
            }
        }
        It 'Returns Pass and Finding does not mention a missing deny-list' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
            $results[0].Finding | Should -Not -Match 'No explicit BlockedDomains deny-list'
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
