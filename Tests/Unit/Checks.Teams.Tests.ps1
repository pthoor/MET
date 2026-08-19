BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"

    # Stub EXO cmdlets needed by Teams002
    function Get-AtpPolicyForO365        { [CmdletBinding()] param() }

    # Stub Teams cmdlets needed by Teams003
    function Get-CsTenantFederationConfiguration { [CmdletBinding()] param() }
    function Get-CsTeamsMeetingPolicy            { [CmdletBinding()] param() }
    function Get-CsTeamsChannelsPolicy           { [CmdletBinding()] param() }

    # Stub cmdlets needed by Teams004
    function Get-TeamsProtectionPolicy     { [CmdletBinding()] param() }
    function Get-TeamsProtectionPolicyRule { [CmdletBinding()] param() }
    function Get-QuarantinePolicy          { [CmdletBinding()] param([string]$Identity) }
}

Describe 'MET-Teams002 Safe Attachments for Teams' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'Teams' 'MET-Teams002-SafeAttachments.ps1'
    }

    Context 'EnableATPForSPOTeamsODB is true' {
        BeforeAll {
            Mock Get-AtpPolicyForO365 {
                [PSCustomObject]@{ EnableATPForSPOTeamsODB = $true }
            }
        }
        It 'Returns Pass' {
            $results = & $checkFile
            $results | Where-Object CheckId -eq 'MET-Teams002' |
                Select-Object -First 1 |
                ForEach-Object { $_.Result | Should -Be 'Pass' }
        }
    }

    Context 'EnableATPForSPOTeamsODB is false' {
        BeforeAll {
            Mock Get-AtpPolicyForO365 {
                [PSCustomObject]@{ EnableATPForSPOTeamsODB = $false }
            }
        }
        It 'Returns Fail' {
            $results = & $checkFile
            $results | Where-Object CheckId -eq 'MET-Teams002' |
                Select-Object -First 1 |
                ForEach-Object { $_.Result | Should -Be 'Fail' }
        }
    }

    Context 'Get-AtpPolicyForO365 throws' {
        BeforeAll {
            Mock Get-AtpPolicyForO365 { throw 'Access denied' }
        }
        It 'Returns Fail with Error populated' {
            $results = & $checkFile
            $result = $results | Where-Object CheckId -eq 'MET-Teams002' | Select-Object -First 1
            $result.Result | Should -Be 'Fail'
            $result.Error | Should -Match 'Access denied'
        }
    }
}

Describe 'MET-Teams003 Meeting Protection' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'Teams' 'MET-Teams003-MeetingProtection.ps1'
    }

    Context 'All meeting settings are secure' {
        BeforeAll {
            Mock Get-CsTenantFederationConfiguration {
                [PSCustomObject]@{ AllowFederatedUsers = $true; AllowPublicUsers = $false }
            }
            Mock Get-CsTeamsMeetingPolicy {
                [PSCustomObject]@{
                    Identity                              = 'Global'
                    AllowAnonymousUsersToJoinMeeting      = $false
                    AutoAdmittedUsers                     = 'EveryoneInSameAndFederatedCompany'
                    AllowExternalNonTrustedMeetingChat    = $false
                }
            }
            Mock Get-CsTeamsChannelsPolicy {
                [PSCustomObject]@{ Identity = 'Global'; AllowSharedChannelCreation = $false }
            }
        }
        It 'Returns Pass' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
        }
    }

    Context 'Anonymous join is enabled' {
        BeforeAll {
            Mock Get-CsTenantFederationConfiguration {
                [PSCustomObject]@{ AllowFederatedUsers = $true; AllowPublicUsers = $false }
            }
            Mock Get-CsTeamsMeetingPolicy {
                [PSCustomObject]@{
                    Identity                              = 'Global'
                    AllowAnonymousUsersToJoinMeeting      = $true
                    AutoAdmittedUsers                     = 'EveryoneInSameAndFederatedCompany'
                    AllowExternalNonTrustedMeetingChat    = $false
                }
            }
            Mock Get-CsTeamsChannelsPolicy {
                [PSCustomObject]@{ Identity = 'Global'; AllowSharedChannelCreation = $false }
            }
        }
        It 'Returns Fail and mentions anonymous' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Finding | Should -Match '[Aa]nonymous'
        }
    }

    Context 'AutoAdmittedUsers is Everyone' {
        BeforeAll {
            Mock Get-CsTenantFederationConfiguration {
                [PSCustomObject]@{ AllowFederatedUsers = $true; AllowPublicUsers = $false }
            }
            Mock Get-CsTeamsMeetingPolicy {
                [PSCustomObject]@{
                    Identity                              = 'Global'
                    AllowAnonymousUsersToJoinMeeting      = $false
                    AutoAdmittedUsers                     = 'Everyone'
                    AllowExternalNonTrustedMeetingChat    = $false
                }
            }
            Mock Get-CsTeamsChannelsPolicy {
                [PSCustomObject]@{ Identity = 'Global'; AllowSharedChannelCreation = $false }
            }
        }
        It 'Returns Fail and mentions lobby' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Finding | Should -Match 'Everyone'
        }
    }

    Context 'A non-Global (custom) meeting policy has anonymous join enabled' {
        BeforeAll {
            Mock Get-CsTenantFederationConfiguration {
                [PSCustomObject]@{ AllowFederatedUsers = $true; AllowPublicUsers = $false }
            }
            Mock Get-CsTeamsMeetingPolicy {
                @(
                    [PSCustomObject]@{
                        Identity                              = 'Global'
                        AllowAnonymousUsersToJoinMeeting      = $false
                        AutoAdmittedUsers                     = 'EveryoneInSameAndFederatedCompany'
                        AllowExternalNonTrustedMeetingChat    = $false
                        AllowPSTNUsersToBypassLobby           = $false
                    },
                    [PSCustomObject]@{
                        Identity                              = 'Tag:LaxMeetings'
                        AllowAnonymousUsersToJoinMeeting      = $true
                        AutoAdmittedUsers                     = 'EveryoneInSameAndFederatedCompany'
                        AllowExternalNonTrustedMeetingChat    = $false
                        AllowPSTNUsersToBypassLobby           = $false
                    }
                )
            }
            Mock Get-CsTeamsChannelsPolicy {
                [PSCustomObject]@{ Identity = 'Global'; AllowSharedChannelCreation = $false }
            }
        }
        It 'Returns Fail and names the custom policy, not just Global' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Finding | Should -Match 'Tag:LaxMeetings'
        }
    }

    Context 'A meeting policy allows PSTN users to bypass the lobby' {
        BeforeAll {
            Mock Get-CsTenantFederationConfiguration {
                [PSCustomObject]@{ AllowFederatedUsers = $true; AllowPublicUsers = $false }
            }
            Mock Get-CsTeamsMeetingPolicy {
                [PSCustomObject]@{
                    Identity                              = 'Global'
                    AllowAnonymousUsersToJoinMeeting      = $false
                    AutoAdmittedUsers                     = 'EveryoneInSameAndFederatedCompany'
                    AllowExternalNonTrustedMeetingChat    = $false
                    AllowPSTNUsersToBypassLobby           = $true
                }
            }
            Mock Get-CsTeamsChannelsPolicy {
                [PSCustomObject]@{ Identity = 'Global'; AllowSharedChannelCreation = $false }
            }
        }
        It 'Flags the PSTN lobby bypass in the Finding' {
            $results = & $checkFile
            $results[0].Finding | Should -Match 'PSTN callers bypass the lobby'
        }
    }

    Context 'Meeting policy retrieval fails' {
        BeforeAll {
            Mock Get-CsTenantFederationConfiguration {
                [PSCustomObject]@{ AllowFederatedUsers = $true; AllowPublicUsers = $false }
            }
            Mock Get-CsTeamsMeetingPolicy { throw 'Teams meeting policy unavailable' }
            Mock Get-CsTeamsChannelsPolicy {
                [PSCustomObject]@{ Identity = 'Global'; AllowSharedChannelCreation = $false }
            }
        }

        It 'Returns Warning instead of false Pass' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'Could not retrieve Teams meeting policies'
        }
    }
}

Describe 'MET-Teams004 ZAP for Teams' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'Teams' 'MET-Teams004-ZAPForTeams.ps1'
    }

    Context 'ZAP enabled, quarantine tags admin-only, no rule exceptions' {
        BeforeAll {
            Mock Get-TeamsProtectionPolicy {
                [PSCustomObject]@{
                    ZapEnabled                       = $true
                    MalwareQuarantineTag              = 'AdminOnlyAccessPolicy'
                    HighConfidencePhishQuarantineTag  = 'AdminOnlyAccessPolicy'
                }
            }
            Mock Get-TeamsProtectionPolicyRule { @() }
        }
        It 'Returns Pass' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
        }
    }

    Context 'ZAP disabled' {
        BeforeAll {
            Mock Get-TeamsProtectionPolicy {
                [PSCustomObject]@{
                    ZapEnabled                       = $false
                    MalwareQuarantineTag              = 'AdminOnlyAccessPolicy'
                    HighConfidencePhishQuarantineTag  = 'AdminOnlyAccessPolicy'
                }
            }
            Mock Get-TeamsProtectionPolicyRule { @() }
        }
        It 'Returns Fail' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
        }
    }

    Context 'An enabled protection rule has exceptions and everything else is compliant' {
        BeforeAll {
            Mock Get-TeamsProtectionPolicy {
                [PSCustomObject]@{
                    ZapEnabled                       = $true
                    MalwareQuarantineTag              = 'AdminOnlyAccessPolicy'
                    HighConfidencePhishQuarantineTag  = 'AdminOnlyAccessPolicy'
                }
            }
            Mock Get-TeamsProtectionPolicyRule {
                [PSCustomObject]@{
                    Name                       = 'DefaultRule'
                    State                      = 'Enabled'
                    ExceptIfSentTo             = @('user1@contoso.com', 'user2@contoso.com')
                    ExceptIfSentToMemberOf     = @()
                    ExceptIfRecipientDomainIs  = @()
                }
            }
        }
        It 'Returns Warning, not Fail, and mentions the excepted recipients' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'excepts'
            $results[0].Finding | Should -Match '2 recipient'
        }
    }

    Context 'An enabled protection rule has exceptions and ZAP is also disabled' {
        BeforeAll {
            Mock Get-TeamsProtectionPolicy {
                [PSCustomObject]@{
                    ZapEnabled                       = $false
                    MalwareQuarantineTag              = 'AdminOnlyAccessPolicy'
                    HighConfidencePhishQuarantineTag  = 'AdminOnlyAccessPolicy'
                }
            }
            Mock Get-TeamsProtectionPolicyRule {
                [PSCustomObject]@{
                    Name                       = 'DefaultRule'
                    State                      = 'Enabled'
                    ExceptIfSentTo             = @()
                    ExceptIfSentToMemberOf     = @('SalesTeam')
                    ExceptIfRecipientDomainIs  = @()
                }
            }
        }
        It 'Stays Fail (does not get downgraded by the exception warning) and still mentions the exception' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Finding | Should -Match 'excepts'
        }
    }

    Context 'A disabled protection rule has exceptions' {
        BeforeAll {
            Mock Get-TeamsProtectionPolicy {
                [PSCustomObject]@{
                    ZapEnabled                       = $true
                    MalwareQuarantineTag              = 'AdminOnlyAccessPolicy'
                    HighConfidencePhishQuarantineTag  = 'AdminOnlyAccessPolicy'
                }
            }
            Mock Get-TeamsProtectionPolicyRule {
                [PSCustomObject]@{
                    Name                       = 'DisabledRule'
                    State                      = 'Disabled'
                    ExceptIfSentTo             = @('user1@contoso.com')
                    ExceptIfSentToMemberOf     = @()
                    ExceptIfRecipientDomainIs  = @()
                }
            }
        }
        It 'Ignores exceptions on disabled rules and returns Pass' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
        }
    }

    Context 'Get-TeamsProtectionPolicyRule throws' {
        BeforeAll {
            Mock Get-TeamsProtectionPolicy {
                [PSCustomObject]@{
                    ZapEnabled                       = $true
                    MalwareQuarantineTag              = 'AdminOnlyAccessPolicy'
                    HighConfidencePhishQuarantineTag  = 'AdminOnlyAccessPolicy'
                }
            }
            Mock Get-TeamsProtectionPolicyRule { throw 'Teams protection policy rule retrieval unavailable' }
        }
        It 'Does not fail purely because rules could not be retrieved' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
        }
    }

    Context 'Get-TeamsProtectionPolicy retrieval fails' {
        BeforeAll {
            Mock Get-TeamsProtectionPolicy { throw 'Teams protection policy unavailable' }
        }
        It 'Returns Fail with an error message' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Error | Should -Not -BeNullOrEmpty
        }
    }
}
