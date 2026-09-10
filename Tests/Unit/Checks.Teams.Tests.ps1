BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METEndUserQuarantinePermission.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"

    # Stub Teams cmdlets needed by Teams003
    function Get-CsTenantFederationConfiguration { [CmdletBinding()] param() }
    function Get-CsTeamsMeetingPolicy            { [CmdletBinding()] param() }
    function Get-CsTeamsChannelsPolicy           { [CmdletBinding()] param() }

    # Stub cmdlets needed by Teams004
    function Get-TeamsProtectionPolicy     { [CmdletBinding()] param() }
    function Get-TeamsProtectionPolicyRule { [CmdletBinding()] param() }
    function Get-QuarantinePolicy          { [CmdletBinding()] param([string]$Identity,[string]$QuarantinePolicyType) }
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
                    Identity                                    = 'Global'
                    AllowAnonymousUsersToJoinMeeting            = $false
                    AutoAdmittedUsers                           = 'EveryoneInSameAndFederatedCompany'
                    AllowExternalNonTrustedMeetingChat          = $false
                    AllowPSTNUsersToBypassLobby                 = $false
                    AllowExternalParticipantGiveRequestControl  = $false
                    AllowAnonymousUsersToStartMeeting           = $false
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

        It 'Returns Warning instead of false Pass even though the other cmdlets returned clean data' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
        }

        It 'Records the retrieval failure in the Error field, not the Finding' {
            $results = & $checkFile
            $results[0].Error   | Should -Match 'Could not retrieve Teams meeting policies'
            $results[0].Finding | Should -Not -Match 'Could not retrieve'
            $results[0].Result  | Should -Not -Be 'Pass'
        }
    }

    Context 'Every meeting protection cmdlet fails' {
        BeforeAll {
            Mock Get-CsTenantFederationConfiguration { throw 'Tenant federation configuration unavailable' }
            Mock Get-CsTeamsMeetingPolicy { throw 'Teams meeting policy unavailable' }
            Mock Get-CsTeamsChannelsPolicy { throw 'Teams channels policy unavailable' }
        }

        It 'Records every retrieval failure in the Error field, not the Finding' {
            $results = & $checkFile
            $results[0].Result  | Should -Be 'Warning'
            $results[0].Error   | Should -Match 'Could not retrieve tenant federation configuration'
            $results[0].Error   | Should -Match 'Could not retrieve Teams meeting policies'
            $results[0].Error   | Should -Match 'Could not retrieve Teams channel policy'
            $results[0].Finding | Should -Not -Match 'Could not retrieve'
        }
    }

    Context 'A meeting policy lets external participants request screen control' {
        BeforeAll {
            Mock Get-CsTenantFederationConfiguration {
                [PSCustomObject]@{ AllowFederatedUsers = $true; AllowPublicUsers = $false }
            }
            Mock Get-CsTeamsMeetingPolicy {
                @(
                    [PSCustomObject]@{
                        Identity                                   = 'Global'
                        AllowAnonymousUsersToJoinMeeting           = $false
                        AutoAdmittedUsers                          = 'EveryoneInSameAndFederatedCompany'
                        AllowExternalNonTrustedMeetingChat         = $false
                        AllowPSTNUsersToBypassLobby                = $false
                        AllowExternalParticipantGiveRequestControl = $false
                        AllowAnonymousUsersToStartMeeting          = $false
                    },
                    [PSCustomObject]@{
                        Identity                                   = 'Tag:VendorMeetings'
                        AllowAnonymousUsersToJoinMeeting           = $false
                        AutoAdmittedUsers                          = 'EveryoneInSameAndFederatedCompany'
                        AllowExternalNonTrustedMeetingChat         = $false
                        AllowPSTNUsersToBypassLobby                = $false
                        AllowExternalParticipantGiveRequestControl = $true
                        AllowAnonymousUsersToStartMeeting          = $false
                    }
                )
            }
            Mock Get-CsTeamsChannelsPolicy {
                [PSCustomObject]@{ Identity = 'Global'; AllowSharedChannelCreation = $false }
            }
        }
        It 'Returns Warning and names the policy granting screen control' {
            $results = & $checkFile
            $results[0].CheckId | Should -Be 'MET-Teams003'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'control of a shared screen'
            $results[0].Finding | Should -Match 'Tag:VendorMeetings'
        }
    }

    Context 'A meeting policy lets anonymous users start meetings' {
        BeforeAll {
            Mock Get-CsTenantFederationConfiguration {
                [PSCustomObject]@{ AllowFederatedUsers = $true; AllowPublicUsers = $false }
            }
            Mock Get-CsTeamsMeetingPolicy {
                [PSCustomObject]@{
                    Identity                                   = 'Global'
                    AllowAnonymousUsersToJoinMeeting           = $false
                    AutoAdmittedUsers                          = 'EveryoneInSameAndFederatedCompany'
                    AllowExternalNonTrustedMeetingChat         = $false
                    AllowPSTNUsersToBypassLobby                = $false
                    AllowExternalParticipantGiveRequestControl = $false
                    AllowAnonymousUsersToStartMeeting          = $true
                }
            }
            Mock Get-CsTeamsChannelsPolicy {
                [PSCustomObject]@{ Identity = 'Global'; AllowSharedChannelCreation = $false }
            }
        }
        It 'Returns Fail and explains that no organiser is required' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Finding | Should -Match 'start a meeting with no organiser present'
        }
    }

    Context 'Both new properties are set to secure values' {
        BeforeAll {
            Mock Get-CsTenantFederationConfiguration {
                [PSCustomObject]@{ AllowFederatedUsers = $true; AllowPublicUsers = $false }
            }
            Mock Get-CsTeamsMeetingPolicy {
                [PSCustomObject]@{
                    Identity                                   = 'Global'
                    AllowAnonymousUsersToJoinMeeting           = $false
                    AutoAdmittedUsers                          = 'EveryoneInSameAndFederatedCompany'
                    AllowExternalNonTrustedMeetingChat         = $false
                    AllowPSTNUsersToBypassLobby                = $false
                    AllowExternalParticipantGiveRequestControl = $false
                    AllowAnonymousUsersToStartMeeting          = $false
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

    Context 'The meeting policy object omits the screen-control and anonymous-start properties' {
        BeforeAll {
            Mock Get-CsTenantFederationConfiguration {
                [PSCustomObject]@{ AllowFederatedUsers = $true; AllowPublicUsers = $false }
            }
            Mock Get-CsTeamsMeetingPolicy {
                [PSCustomObject]@{
                    Identity                           = 'Global'
                    AllowAnonymousUsersToJoinMeeting   = $false
                    AutoAdmittedUsers                  = 'EveryoneInSameAndFederatedCompany'
                    AllowExternalNonTrustedMeetingChat = $false
                    AllowPSTNUsersToBypassLobby        = $false
                }
            }
            Mock Get-CsTeamsChannelsPolicy {
                [PSCustomObject]@{ Identity = 'Global'; AllowSharedChannelCreation = $false }
            }
        }
        It 'Warns that the absent properties were not confirmed rather than treating them as not enabled' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Not -Match 'control of a shared screen'
            $results[0].Finding | Should -Not -Match 'start a meeting with no organiser present'
        }
    }

    # Every meeting-policy assertion in this check is an -eq $true comparison, so a
    # policy object that returns none of the properties produces no insecure-value
    # match on its own; the absence tracking added alongside those six filters is what
    # keeps this from reading as a clean tenant.
    Context 'The meeting policy object omits every property the check reads' {
        BeforeAll {
            Mock Get-CsTenantFederationConfiguration {
                [PSCustomObject]@{ AllowFederatedUsers = $true; AllowPublicUsers = $false }
            }
            Mock Get-CsTeamsMeetingPolicy {
                [PSCustomObject]@{ Identity = 'Global' }
            }
            Mock Get-CsTeamsChannelsPolicy {
                [PSCustomObject]@{ Identity = 'Global'; AllowSharedChannelCreation = $false }
            }
        }

        It 'Returns Warning and reports the settings as unobserved rather than correctly configured' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Not -Match 'correctly configured'
            $results[0].Finding | Should -Match 'not returned'
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
        It 'Returns Warning, not Pass, because rule exceptions narrowing ZAP coverage went unverified' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'unverified'
            $results[0].Error   | Should -Not -BeNullOrEmpty
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

    # The quarantine tag is resolved to a policy object and read as
    # $policy.EndUserQuarantinePermissions.PermissionToRelease. A policy object that
    # omits EndUserQuarantinePermissions makes the whole expression $null, so the
    # self-release test must not silently treat that as "prevented".
    Context 'The assigned quarantine policy omits EndUserQuarantinePermissions' {
        BeforeAll {
            Mock Get-TeamsProtectionPolicy {
                [PSCustomObject]@{
                    ZapEnabled                       = $true
                    MalwareQuarantineTag             = 'ContosoCustomTag'
                    HighConfidencePhishQuarantineTag = 'ContosoCustomTag'
                }
            }
            Mock Get-TeamsProtectionPolicyRule { @() }
            Mock Get-QuarantinePolicy { [PSCustomObject]@{ Name = 'ContosoCustomTag' } }
        }

        It 'Reports the release permission as unconfirmed instead of claiming users cannot self-release' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Not -Match 'quarantine policies do not allow user self-release'
            $results[0].Finding | Should -Match 'not returned'
        }
    }
}
