BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"
    function Get-CsTeamsGuestMessagingConfiguration { [CmdletBinding()] param() }
    function Get-CsTeamsGuestCallingConfiguration   { [CmdletBinding()] param() }
}

Describe 'MET-Teams007 Guest Configuration' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'Teams' 'MET-Teams007-GuestConfiguration.ps1'
    }

    Context 'guest chat and calling both restricted' {
        BeforeAll {
            Mock Get-CsTeamsGuestMessagingConfiguration {
                [PSCustomObject]@{
                    AllowUserEditMessage   = $true
                    AllowUserDeleteMessage = $true
                    AllowUserChat          = $false
                    AllowGiphy             = $true
                    AllowMemes             = $true
                    AllowStickers          = $true
                }
            }
            Mock Get-CsTeamsGuestCallingConfiguration {
                [PSCustomObject]@{ AllowPrivateCalling = $false }
            }
        }
        It 'Returns Pass' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
        }
    }

    Context 'guest chat allowed' {
        BeforeAll {
            Mock Get-CsTeamsGuestMessagingConfiguration {
                [PSCustomObject]@{
                    AllowUserEditMessage   = $true
                    AllowUserDeleteMessage = $true
                    AllowUserChat          = $true
                    AllowGiphy             = $false
                    AllowMemes             = $false
                    AllowStickers          = $false
                }
            }
            Mock Get-CsTeamsGuestCallingConfiguration {
                [PSCustomObject]@{ AllowPrivateCalling = $false }
            }
        }
        It 'Returns Warning and mentions initiate 1:1 chat' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'initiate 1:1 chat'
        }
    }

    Context 'guest private calling allowed' {
        BeforeAll {
            Mock Get-CsTeamsGuestMessagingConfiguration {
                [PSCustomObject]@{
                    AllowUserEditMessage   = $true
                    AllowUserDeleteMessage = $true
                    AllowUserChat          = $false
                    AllowGiphy             = $true
                    AllowMemes             = $true
                    AllowStickers          = $true
                }
            }
            Mock Get-CsTeamsGuestCallingConfiguration {
                [PSCustomObject]@{ AllowPrivateCalling = $true }
            }
        }
        It 'Returns Warning and mentions private (1:1) calls' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'private \(1:1\) calls'
        }
    }

    Context 'both cmdlets throw' {
        BeforeAll {
            Mock Get-CsTeamsGuestMessagingConfiguration { throw 'Guest messaging config unavailable' }
            Mock Get-CsTeamsGuestCallingConfiguration { throw 'Guest calling config unavailable' }
        }
        It 'Returns Warning and mentions both retrieval failures' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'Could not retrieve Teams guest messaging configuration'
            $results[0].Finding | Should -Match 'Could not retrieve Teams guest calling configuration'
        }
    }
}
