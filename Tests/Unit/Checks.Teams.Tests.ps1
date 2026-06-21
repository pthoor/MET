BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"

    # Stub EXO cmdlets needed by Teams001/002
    function Get-SafeLinksPolicy         { [CmdletBinding()] param() }
    function Get-SafeAttachmentPolicy    { [CmdletBinding()] param() }

    # Stub Teams cmdlets needed by Teams003
    function Get-CsTenantFederationConfiguration { [CmdletBinding()] param() }
    function Get-CsTeamsMeetingPolicy            { [CmdletBinding()] param() }
    function Get-CsTeamsChannelsPolicy           { [CmdletBinding()] param() }
}

Describe 'MET-Teams001 Safe Links for Teams' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'Teams' 'MET-Teams001-SafeLinks.ps1'
    }

    Context 'EnableSafeLinksForTeams is true' {
        BeforeAll {
            Mock Get-SafeLinksPolicy {
                [PSCustomObject]@{
                    Name                      = 'ContosoPol'
                    EnableSafeLinksForTeams   = $true
                    EnableSafeLinksForEmail   = $true
                    EnableSafeLinksForOffice  = $true
                    TrackClicks               = $true
                    EnableForInternalSenders  = $true
                    ScanUrls                  = $true
                    AllowClickThrough         = $false
                }
            }
        }
        It 'Returns Pass' {
            $results = & $checkFile
            $results | Where-Object CheckId -eq 'MET-Teams001' |
                Select-Object -First 1 |
                ForEach-Object { $_.Result | Should -Be 'Pass' }
        }
    }

    Context 'EnableSafeLinksForTeams is false on all policies' {
        BeforeAll {
            Mock Get-SafeLinksPolicy {
                [PSCustomObject]@{
                    Name                    = 'Default'
                    EnableSafeLinksForTeams = $false
                    EnableSafeLinksForEmail = $true
                    EnableSafeLinksForOffice = $true
                    TrackClicks             = $true
                    EnableForInternalSenders= $true
                    ScanUrls                = $true
                    AllowClickThrough       = $false
                }
            }
        }
        It 'Returns Fail' {
            $results = & $checkFile
            $results | Where-Object CheckId -eq 'MET-Teams001' |
                Select-Object -First 1 |
                ForEach-Object { $_.Result | Should -Be 'Fail' }
        }
    }

    Context 'No policies at all' {
        BeforeAll { Mock Get-SafeLinksPolicy { @() } }
        It 'Returns Fail' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
        }
    }
}

Describe 'MET-Teams002 Safe Attachments for Teams' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'Teams' 'MET-Teams002-SafeAttachments.ps1'
    }

    Context 'EnableSafeAttachmentsForTeams is true' {
        BeforeAll {
            Mock Get-SafeAttachmentPolicy {
                [PSCustomObject]@{ Name = 'Policy1'; Enable = $true; Action = 'Block'; EnableSafeAttachmentsForTeams = $true }
            }
        }
        It 'Returns Pass' {
            $results = & $checkFile
            $results | Where-Object CheckId -eq 'MET-Teams002' |
                Select-Object -First 1 |
                ForEach-Object { $_.Result | Should -Be 'Pass' }
        }
    }

    Context 'EnableSafeAttachmentsForTeams is false' {
        BeforeAll {
            Mock Get-SafeAttachmentPolicy {
                [PSCustomObject]@{ Name = 'Policy1'; Enable = $true; Action = 'Block'; EnableSafeAttachmentsForTeams = $false }
            }
        }
        It 'Returns Fail' {
            $results = & $checkFile
            $results | Where-Object CheckId -eq 'MET-Teams002' |
                Select-Object -First 1 |
                ForEach-Object { $_.Result | Should -Be 'Fail' }
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
}
