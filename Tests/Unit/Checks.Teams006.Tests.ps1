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
                    BlockAllSubdomains                          = $true
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
                    BlockAllSubdomains                          = $true
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
                    BlockAllSubdomains                          = $true
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
                    BlockAllSubdomains                          = $true
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
                    BlockAllSubdomains                          = $true
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
                    BlockAllSubdomains                          = $true
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
                    BlockAllSubdomains                          = $true
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

    Context 'Open federation with BlockedDomains populated but subdomains not blocked' {
        BeforeAll {
            Mock Get-CsTenantFederationConfiguration {
                [PSCustomObject]@{
                    AllowFederatedUsers                        = $true
                    AllowedDomains                              = 'AllowAllKnownDomains'
                    AllowTeamsConsumer                          = $false
                    AllowTeamsConsumerInbound                   = $false
                    BlockedDomains                              = @('malicious.com')
                    BlockAllSubdomains                          = $false
                    AllowPublicUsers                            = $false
                }
            }
        }
        It 'Explains that subdomains of blocked domains remain reachable' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Fail'
            $results[0].Finding | Should -Match 'BlockAllSubdomains is disabled'
            $results[0].Finding | Should -Match 'subdomain'
            $results[0].Recommendation | Should -Match '-BlockAllSubdomains \$true'
        }
    }

    Context 'Specific-domain allow-list with BlockedDomains populated and subdomains not blocked' {
        BeforeAll {
            Mock Get-CsTenantFederationConfiguration {
                [PSCustomObject]@{
                    AllowFederatedUsers                        = $true
                    AllowedDomains                              = 'SomeScopedDomainsObject'
                    AllowTeamsConsumer                          = $false
                    AllowTeamsConsumerInbound                   = $false
                    BlockedDomains                              = @('malicious.com')
                    BlockAllSubdomains                          = $false
                    AllowPublicUsers                            = $false
                }
            }
        }
        It 'Does not flag subdomain coverage of a deny-list the allow-list makes inactive' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Pass'
            $results[0].Finding | Should -Not -Match 'BlockAllSubdomains'
        }
    }

    Context 'Open federation with BlockedDomains populated and BlockAllSubdomains not returned' {
        BeforeAll {
            Mock Get-CsTenantFederationConfiguration {
                [PSCustomObject]@{
                    AllowFederatedUsers                        = $true
                    AllowedDomains                              = 'AllowAllKnownDomains'
                    AllowTeamsConsumer                          = $false
                    AllowTeamsConsumerInbound                   = $false
                    BlockedDomains                              = @('malicious.com')
                    AllowPublicUsers                            = $false
                }
            }
        }
        It 'Keeps the federation finding and reports subdomain coverage as a separate unassessed result' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 2
            $results[0].Result | Should -Be 'Fail'
            $results[0].Finding | Should -Not -Match 'BlockAllSubdomains'
            $results[1].Name | Should -Be 'Blocked Domain Subdomain Coverage'
            $results[1].Result | Should -Be 'NotApplicable'
            $results[1].Finding | Should -Match 'not established'
            $results[1].Finding | Should -Match 'rather than a pass'
            $results[1].Error | Should -Match 'BlockAllSubdomains'
        }
    }

    Context 'BlockedDomains empty' {
        BeforeAll {
            Mock Get-CsTenantFederationConfiguration {
                [PSCustomObject]@{
                    AllowFederatedUsers                        = $true
                    AllowedDomains                              = 'SomeScopedDomainsObject'
                    AllowTeamsConsumer                          = $false
                    AllowTeamsConsumerInbound                   = $false
                    BlockedDomains                              = @()
                    BlockAllSubdomains                          = $false
                    AllowPublicUsers                            = $false
                }
            }
        }
        It 'Does not raise subdomain coverage when nothing is blocked' {
            $results = & $checkFile
            $results[0].Finding | Should -Not -Match 'BlockAllSubdomains'
        }
    }

    Context 'cmdlet throws (module absent)' {
        BeforeAll {
            Mock Get-CsTenantFederationConfiguration { throw 'Teams federation configuration unavailable' }
        }
        It 'Returns Warning instead of false Pass' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
        }

        It 'Records the retrieval failure in the Error field, not the Finding' {
            $results = & $checkFile
            $results[0].Error   | Should -Match 'Could not retrieve tenant federation configuration'
            $results[0].Finding | Should -Not -Match 'Could not retrieve'
            $results[0].Result  | Should -Not -Be 'Pass'
        }
    }
}
