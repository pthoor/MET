BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"

    function Get-CsTenantFederationConfiguration { [CmdletBinding()] param() }
    function Get-CsTeamsMeetingPolicy            { [CmdletBinding()] param() }
    function Get-CsTeamsChannelsPolicy           { [CmdletBinding()] param() }

    $checkFile = Join-Path $root 'Checks' 'Teams' 'MET-Teams003-MeetingProtection.ps1'

    $secureFederation = [PSCustomObject]@{ AllowFederatedUsers = $true; AllowPublicUsers = $false }
    $secureChannelPolicy = [PSCustomObject]@{ Identity = 'Global'; AllowSharedChannelCreation = $false }
}

Describe 'MET-Teams003 Meeting Protection - unobserved meeting settings' {
    BeforeEach {
        Mock Get-CsTenantFederationConfiguration { $secureFederation }
        Mock Get-CsTeamsChannelsPolicy { $secureChannelPolicy }
    }

    Context 'A single meeting policy carries none of the six settings' {
        BeforeAll {
            Mock Get-CsTeamsMeetingPolicy {
                [PSCustomObject]@{ Identity = 'Global' }
            }
        }

        It 'Returns Warning rather than reporting the meeting configuration as correct' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Warning'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].Finding | Should -Not -Match 'correctly configured'
        }

        It 'Names every unobserved setting and the policy it was missing from' {
            $results = @(& $checkFile)
            $results[0].Finding | Should -Match 'AllowAnonymousUsersToJoinMeeting'
            $results[0].Finding | Should -Match 'AutoAdmittedUsers'
            $results[0].Finding | Should -Match 'AllowExternalNonTrustedMeetingChat'
            $results[0].Finding | Should -Match 'AllowPSTNUsersToBypassLobby'
            $results[0].Finding | Should -Match 'AllowExternalParticipantGiveRequestControl'
            $results[0].Finding | Should -Match 'AllowAnonymousUsersToStartMeeting'
            $results[0].Finding | Should -Match 'Global'
        }

        It 'Names Get-CsTeamsMeetingPolicy and the unreturned properties in the Error field' {
            $results = @(& $checkFile)
            $results[0].Error | Should -Match 'Get-CsTeamsMeetingPolicy'
            $results[0].Error | Should -Match 'AllowAnonymousUsersToJoinMeeting'
        }
    }

    Context 'One of two policies is missing only AllowPSTNUsersToBypassLobby' {
        BeforeAll {
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
                        Identity                                   = 'Tag:LegacyPolicy'
                        AllowAnonymousUsersToJoinMeeting           = $false
                        AutoAdmittedUsers                          = 'EveryoneInSameAndFederatedCompany'
                        AllowExternalNonTrustedMeetingChat         = $false
                        AllowExternalParticipantGiveRequestControl = $false
                        AllowAnonymousUsersToStartMeeting          = $false
                    }
                )
            }
        }

        It 'Returns Warning naming only the missing setting and only the policy missing it' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'AllowPSTNUsersToBypassLobby'
            $results[0].Finding | Should -Match 'Tag:LegacyPolicy'
            $results[0].Finding | Should -Not -Match 'AllowAnonymousUsersToJoinMeeting was not returned'
            $results[0].Finding | Should -Not -Match 'AutoAdmittedUsers was not returned'
            $results[0].Finding | Should -Not -Match 'AllowExternalNonTrustedMeetingChat was not returned'
            $results[0].Finding | Should -Not -Match 'AllowExternalParticipantGiveRequestControl was not returned'
            $results[0].Finding | Should -Not -Match 'AllowAnonymousUsersToStartMeeting was not returned'
        }
    }

    Context 'One policy has an explicit insecure value and a second policy is missing that same setting' {
        BeforeAll {
            Mock Get-CsTeamsMeetingPolicy {
                @(
                    [PSCustomObject]@{
                        Identity                                   = 'Global'
                        AllowAnonymousUsersToJoinMeeting           = $true
                        AutoAdmittedUsers                          = 'EveryoneInSameAndFederatedCompany'
                        AllowExternalNonTrustedMeetingChat         = $false
                        AllowPSTNUsersToBypassLobby                = $false
                        AllowExternalParticipantGiveRequestControl = $false
                        AllowAnonymousUsersToStartMeeting          = $false
                    },
                    [PSCustomObject]@{
                        Identity                                   = 'Tag:PartialPolicy'
                        AutoAdmittedUsers                          = 'EveryoneInSameAndFederatedCompany'
                        AllowExternalNonTrustedMeetingChat         = $false
                        AllowPSTNUsersToBypassLobby                = $false
                        AllowExternalParticipantGiveRequestControl = $false
                        AllowAnonymousUsersToStartMeeting          = $false
                    }
                )
            }
        }

        It 'Still fires the existing anonymous-join issue and also reports the absent one' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Fail'
            $results[0].Finding | Should -Match 'Anonymous users are allowed to join meetings without being admitted from the lobby'
            $results[0].Finding | Should -Match 'Global'
            $results[0].Finding | Should -Match 'AllowAnonymousUsersToJoinMeeting was not returned'
            $results[0].Finding | Should -Match 'Tag:PartialPolicy'
        }
    }

    Context 'All six settings are present and secure on every policy' {
        BeforeAll {
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
                        AutoAdmittedUsers                          = 'OrganizerOnly'
                        AllowExternalNonTrustedMeetingChat         = $false
                        AllowPSTNUsersToBypassLobby                = $false
                        AllowExternalParticipantGiveRequestControl = $false
                        AllowAnonymousUsersToStartMeeting          = $false
                    }
                )
            }
        }

        It 'Returns the existing clean verdict, unchanged' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Pass'
            $results[0].Finding | Should -Be 'Teams meeting protection settings are correctly configured'
        }
    }

    Context 'Six policies, each missing a different one of the six settings' {
        BeforeAll {
            Mock Get-CsTeamsMeetingPolicy {
                @(
                    [PSCustomObject]@{
                        Identity                                   = 'Tag:MissingJoin'
                        AutoAdmittedUsers                          = 'EveryoneInSameAndFederatedCompany'
                        AllowExternalNonTrustedMeetingChat         = $false
                        AllowPSTNUsersToBypassLobby                = $false
                        AllowExternalParticipantGiveRequestControl = $false
                        AllowAnonymousUsersToStartMeeting          = $false
                    },
                    [PSCustomObject]@{
                        Identity                                   = 'Tag:MissingAutoAdmit'
                        AllowAnonymousUsersToJoinMeeting           = $false
                        AllowExternalNonTrustedMeetingChat         = $false
                        AllowPSTNUsersToBypassLobby                = $false
                        AllowExternalParticipantGiveRequestControl = $false
                        AllowAnonymousUsersToStartMeeting          = $false
                    },
                    [PSCustomObject]@{
                        Identity                                   = 'Tag:MissingChat'
                        AllowAnonymousUsersToJoinMeeting           = $false
                        AutoAdmittedUsers                          = 'EveryoneInSameAndFederatedCompany'
                        AllowPSTNUsersToBypassLobby                = $false
                        AllowExternalParticipantGiveRequestControl = $false
                        AllowAnonymousUsersToStartMeeting          = $false
                    },
                    [PSCustomObject]@{
                        Identity                                   = 'Tag:MissingPstn'
                        AllowAnonymousUsersToJoinMeeting           = $false
                        AutoAdmittedUsers                          = 'EveryoneInSameAndFederatedCompany'
                        AllowExternalNonTrustedMeetingChat         = $false
                        AllowExternalParticipantGiveRequestControl = $false
                        AllowAnonymousUsersToStartMeeting          = $false
                    },
                    [PSCustomObject]@{
                        Identity                                   = 'Tag:MissingGiveControl'
                        AllowAnonymousUsersToJoinMeeting           = $false
                        AutoAdmittedUsers                          = 'EveryoneInSameAndFederatedCompany'
                        AllowExternalNonTrustedMeetingChat         = $false
                        AllowPSTNUsersToBypassLobby                = $false
                        AllowAnonymousUsersToStartMeeting          = $false
                    },
                    [PSCustomObject]@{
                        Identity                                   = 'Tag:MissingAnonStart'
                        AllowAnonymousUsersToJoinMeeting           = $false
                        AutoAdmittedUsers                          = 'EveryoneInSameAndFederatedCompany'
                        AllowExternalNonTrustedMeetingChat         = $false
                        AllowPSTNUsersToBypassLobby                = $false
                        AllowExternalParticipantGiveRequestControl = $false
                    }
                )
            }
        }

        It 'Names all six unobserved settings once each' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'AllowAnonymousUsersToJoinMeeting was not returned'
            $results[0].Finding | Should -Match 'AutoAdmittedUsers was not returned'
            $results[0].Finding | Should -Match 'AllowExternalNonTrustedMeetingChat was not returned'
            $results[0].Finding | Should -Match 'AllowPSTNUsersToBypassLobby was not returned'
            $results[0].Finding | Should -Match 'AllowExternalParticipantGiveRequestControl was not returned'
            $results[0].Finding | Should -Match 'AllowAnonymousUsersToStartMeeting was not returned'
            ($results[0].Finding -split 'was not returned').Count - 1 | Should -Be 6
        }
    }

    Context 'Eight policies all missing the same setting' {
        BeforeAll {
            Mock Get-CsTeamsMeetingPolicy {
                1..8 | ForEach-Object {
                    [PSCustomObject]@{
                        Identity                                   = "Tag:Policy$_"
                        AllowAnonymousUsersToJoinMeeting           = $false
                        AutoAdmittedUsers                          = 'EveryoneInSameAndFederatedCompany'
                        AllowExternalNonTrustedMeetingChat         = $false
                        AllowExternalParticipantGiveRequestControl = $false
                        AllowAnonymousUsersToStartMeeting          = $false
                    }
                }
            }
        }

        It 'Lists five policy names plus a showing-first-of-total suffix' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'Tag:Policy1'
            $results[0].Finding | Should -Match 'Tag:Policy2'
            $results[0].Finding | Should -Match 'Tag:Policy3'
            $results[0].Finding | Should -Match 'Tag:Policy4'
            $results[0].Finding | Should -Match 'Tag:Policy5'
            $results[0].Finding | Should -Not -Match 'Tag:Policy6'
            $results[0].Finding | Should -Match 'showing first 5 of 8'
        }
    }
}
