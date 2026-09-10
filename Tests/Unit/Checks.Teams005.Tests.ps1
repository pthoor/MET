BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"

    function Get-ReportSubmissionPolicy { [CmdletBinding()] param() }
    function Get-CsTeamsMessagingPolicy { [CmdletBinding()] param([string]$Identity) }

    $checkFile = Join-Path $root 'Checks' 'Teams' 'MET-Teams005-TeamsUserReporting.ps1'
}

Describe 'MET-Teams005 Teams User Reporting' {
    BeforeEach {
        Mock Get-CsTeamsMessagingPolicy {
            @([PSCustomObject]@{ Identity = 'Global'; AllowSecurityEndUserReporting = $true })
        }
    }

    Context 'Reporting is monitored, routed to SecOps and enabled in every messaging policy' {
        BeforeEach {
            Mock Get-ReportSubmissionPolicy {
                [PSCustomObject]@{
                    ReportChatMessageEnabled                    = $true
                    ReportChatMessageToCustomizedAddressEnabled = $true
                }
            }
        }

        It 'Returns a single Pass result' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].CheckId  | Should -Be 'MET-Teams005'
            $results[0].Category | Should -Be 'Teams'
            $results[0].Name     | Should -Be 'Teams User Reporting'
            $results[0].Result   | Should -Be 'Pass'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].AffectedObject | Should -Be 'Teams User Reporting Settings'
            $results[0].Error    | Should -BeNullOrEmpty
        }

        It 'Claims all three conditions it actually verified' {
            $results = @(& $checkFile)
            $results[0].Finding | Should -Match 'enabled in the Defender portal'
            $results[0].Finding | Should -Match 'routed to the SecOps mailbox'
            $results[0].Finding | Should -Match 'all Teams messaging policies allow users to report'
        }
    }

    Context 'Monitoring of Teams reported items is disabled' {
        BeforeEach {
            Mock Get-ReportSubmissionPolicy {
                [PSCustomObject]@{
                    ReportChatMessageEnabled                    = $false
                    ReportChatMessageToCustomizedAddressEnabled = $true
                }
            }
        }

        It 'Fails at Medium severity naming the disabled monitoring setting' {
            $results = @(& $checkFile)
            $results[0].Result   | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].Finding  | Should -Match 'Monitor reported items in Microsoft Teams'
            $results[0].Finding  | Should -Match 'is disabled in the Defender portal'
        }

        It 'Does not also claim the SecOps routing gap, which is not reachable while monitoring is off' {
            $results = @(& $checkFile)
            $results[0].Finding | Should -Not -Match 'not copied to the SecOps mailbox'
        }
    }

    Context 'Teams reports are monitored but not copied to the SecOps mailbox' {
        BeforeEach {
            Mock Get-ReportSubmissionPolicy {
                [PSCustomObject]@{
                    ReportChatMessageEnabled                    = $true
                    ReportChatMessageToCustomizedAddressEnabled = $false
                }
            }
        }

        It 'Fails at Medium severity naming the SecOps routing gap' {
            $results = @(& $checkFile)
            $results[0].Result   | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].Finding  | Should -Match 'not copied to the SecOps mailbox'
            $results[0].Finding  | Should -Not -Match 'Monitor reported items in Microsoft Teams'
        }
    }

    Context 'A Teams messaging policy disables the report button' {
        BeforeEach {
            Mock Get-ReportSubmissionPolicy {
                [PSCustomObject]@{
                    ReportChatMessageEnabled                    = $true
                    ReportChatMessageToCustomizedAddressEnabled = $true
                }
            }
            Mock Get-CsTeamsMessagingPolicy {
                @(
                    [PSCustomObject]@{ Identity = 'Global';        AllowSecurityEndUserReporting = $true }
                    [PSCustomObject]@{ Identity = 'Tag:Retail';    AllowSecurityEndUserReporting = $false }
                    [PSCustomObject]@{ Identity = 'Tag:Contractor'; AllowSecurityEndUserReporting = $false }
                )
            }
        }

        It 'Fails naming every offending policy and not the compliant one' {
            $results = @(& $checkFile)
            $results[0].Result   | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].Finding  | Should -Match 'Report a security concern'
            $results[0].Finding  | Should -Match 'Tag:Retail'
            $results[0].Finding  | Should -Match 'Tag:Contractor'
            $results[0].Finding  | Should -Not -Match 'Global'
        }
    }

    Context 'Get-ReportSubmissionPolicy throws' {
        BeforeEach {
            Mock Get-ReportSubmissionPolicy { throw 'Access to the requested object is denied.' }
        }

        It 'Fails once, carrying the exception text in Error rather than the Finding' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result   | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].AffectedObject | Should -Be 'Teams User Reporting Settings'
            $results[0].Finding | Should -Match 'Unable to retrieve report submission policy'
            $results[0].Error   | Should -Match 'Access to the requested object is denied'
            $results[0].Finding | Should -Not -Match 'Access to the requested object is denied'
        }
    }

    Context 'Get-ReportSubmissionPolicy returns nothing without throwing' {
        BeforeEach {
            Mock Get-ReportSubmissionPolicy { }
        }

        It 'Fails rather than silently skipping the assessment' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result   | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].Finding  | Should -Match 'No report submission policy found'
            $results[0].Finding  | Should -Match 'cannot be routed or monitored'
        }
    }

    Context 'The Defender portal side is clean but Teams messaging policies cannot be read' {
        BeforeEach {
            Mock Get-ReportSubmissionPolicy {
                [PSCustomObject]@{
                    ReportChatMessageEnabled                    = $true
                    ReportChatMessageToCustomizedAddressEnabled = $true
                }
            }
            Mock Get-CsTeamsMessagingPolicy { throw 'Run Connect-MicrosoftTeams before running this cmdlet.' }
        }

        It 'Warns instead of passing, since half the assertion went unverified' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result   | Should -Be 'Warning'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].Finding  | Should -Match 'could not be read'
            $results[0].Finding  | Should -Match 'unverified'
            $results[0].Error    | Should -Match 'Connect-MicrosoftTeams'
        }

        It 'Points at the connection that would let the assertion be verified' {
            $results = @(& $checkFile)
            $results[0].Recommendation | Should -Match 'Connect-METSession without -SkipTeams'
        }
    }

    Context 'The Defender portal side has a fault and Teams messaging policies also cannot be read' {
        BeforeEach {
            Mock Get-ReportSubmissionPolicy {
                [PSCustomObject]@{
                    ReportChatMessageEnabled                    = $false
                    ReportChatMessageToCustomizedAddressEnabled = $false
                }
            }
            Mock Get-CsTeamsMessagingPolicy { throw 'Run Connect-MicrosoftTeams before running this cmdlet.' }
        }

        It 'Reports the confirmed Fail rather than downgrading to the unverified Warning' {
            $results = @(& $checkFile)
            $results[0].Result  | Should -Be 'Fail'
            $results[0].Finding | Should -Match 'Monitor reported items in Microsoft Teams'
        }

        It 'Still surfaces that the Teams messaging-policy leg could not be assessed' {
            $results = @(& $checkFile)
            $results[0].Finding | Should -Match 'messaging policies could not be retrieved'
            $results[0].Finding | Should -Match 'unverified rather than a confirmed failure'
            $results[0].Error   | Should -Match 'Connect-MicrosoftTeams'
        }
    }

    Context 'The report submission policy omits ReportChatMessageEnabled' {
        BeforeEach {
            Mock Get-ReportSubmissionPolicy {
                [PSCustomObject]@{ Identity = 'DefaultReportSubmissionPolicy' }
            }
        }

        It 'Does not return Pass on a setting that was never observed' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Not -Be 'Pass'
            $results[0].Result | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'Medium'
        }
    }

    Context 'A Teams messaging policy omits AllowSecurityEndUserReporting' {
        BeforeEach {
            Mock Get-ReportSubmissionPolicy {
                [PSCustomObject]@{
                    ReportChatMessageEnabled                    = $true
                    ReportChatMessageToCustomizedAddressEnabled = $true
                }
            }
            Mock Get-CsTeamsMessagingPolicy {
                @([PSCustomObject]@{ Identity = 'Global' })
            }
        }

        It 'Warns instead of claiming every policy allows reporting, and names the unverified policy' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result   | Should -Be 'Warning'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].Finding  | Should -Match 'Global'
            $results[0].Finding  | Should -Not -Match 'all Teams messaging policies allow users to report'
            $results[0].Error    | Should -Match 'AllowSecurityEndUserReporting'
        }
    }

    Context 'One Teams messaging policy carries the property and one omits it' {
        BeforeEach {
            Mock Get-ReportSubmissionPolicy {
                [PSCustomObject]@{
                    ReportChatMessageEnabled                    = $true
                    ReportChatMessageToCustomizedAddressEnabled = $true
                }
            }
            Mock Get-CsTeamsMessagingPolicy {
                @(
                    [PSCustomObject]@{ Identity = 'Global';   AllowSecurityEndUserReporting = $true }
                    [PSCustomObject]@{ Identity = 'Tag:Sales' }
                )
            }
        }

        It 'Warns naming only the policy that omitted the property, not the one that carried it' {
            $results = @(& $checkFile)
            $results[0].Result   | Should -Be 'Warning'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].Finding  | Should -Match 'Tag:Sales'
            $results[0].Finding  | Should -Not -Match 'all Teams messaging policies allow users to report'
        }
    }

    Context 'Every Teams messaging policy omits AllowSecurityEndUserReporting' {
        BeforeEach {
            Mock Get-ReportSubmissionPolicy {
                [PSCustomObject]@{
                    ReportChatMessageEnabled                    = $true
                    ReportChatMessageToCustomizedAddressEnabled = $true
                }
            }
            Mock Get-CsTeamsMessagingPolicy {
                @(
                    [PSCustomObject]@{ Identity = 'Global' }
                    [PSCustomObject]@{ Identity = 'Tag:Sales' }
                )
            }
        }

        It 'Warns rather than passing when none of the returned policies carried the property' {
            $results = @(& $checkFile)
            $results[0].Result   | Should -Be 'Warning'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].Finding  | Should -Not -Match 'all Teams messaging policies allow users to report'
        }
    }

    Context 'One Teams messaging policy disables the button and another omits the property' {
        BeforeEach {
            Mock Get-ReportSubmissionPolicy {
                [PSCustomObject]@{
                    ReportChatMessageEnabled                    = $true
                    ReportChatMessageToCustomizedAddressEnabled = $true
                }
            }
            Mock Get-CsTeamsMessagingPolicy {
                @(
                    [PSCustomObject]@{ Identity = 'Tag:Retail'; AllowSecurityEndUserReporting = $false }
                    [PSCustomObject]@{ Identity = 'Tag:Sales' }
                )
            }
        }

        It 'Fails, and the Finding mentions both the disabled policy and the unestablished one' {
            $results = @(& $checkFile)
            $results[0].Result   | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].Finding  | Should -Match 'Tag:Retail'
            $results[0].Finding  | Should -Match 'Tag:Sales'
        }
    }

    Context 'Get-CsTeamsMessagingPolicy returns no policies at all' {
        BeforeEach {
            Mock Get-ReportSubmissionPolicy {
                [PSCustomObject]@{
                    ReportChatMessageEnabled                    = $true
                    ReportChatMessageToCustomizedAddressEnabled = $true
                }
            }
            Mock Get-CsTeamsMessagingPolicy { @() }
        }

        It 'Warns rather than passing when no messaging policies were returned' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result   | Should -Be 'Warning'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].Finding  | Should -Not -Match 'all Teams messaging policies allow users to report'
        }

        It 'States why an unconfirmed state is not reported as a pass' {
            $results = @(& $checkFile)
            $results[0].Finding | Should -Match 'reported as unassessed rather than a pass'
        }

        It 'Reports the zero-policies Error accurately rather than claiming one or more policies were read' {
            $results = @(& $checkFile)
            $results[0].Error | Should -Match 'no Teams messaging policies'
            $results[0].Error | Should -Not -Match 'one or more'
        }
    }

    # This is the live false Pass this wave exists to close: a messaging policy that
    # returns AllowSecurityEndUserReporting as $null is neither confirmed enabled nor
    # confirmed disabled, so it must not satisfy the Pass condition the way an absent
    # property already correctly does not.
    Context 'A Teams messaging policy has AllowSecurityEndUserReporting present but explicitly $null' {
        BeforeEach {
            Mock Get-ReportSubmissionPolicy {
                [PSCustomObject]@{
                    ReportChatMessageEnabled                    = $true
                    ReportChatMessageToCustomizedAddressEnabled = $true
                }
            }
            Mock Get-CsTeamsMessagingPolicy {
                @([PSCustomObject]@{ Identity = 'Global'; AllowSecurityEndUserReporting = $null })
            }
        }

        It 'Warns instead of passing on a value it never observed, and names the policy' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result   | Should -Be 'Warning'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].Finding  | Should -Match 'Global'
            $results[0].Finding  | Should -Not -Match 'all Teams messaging policies allow users to report'
            $results[0].Error    | Should -Match 'AllowSecurityEndUserReporting'
        }

        It 'States why an unconfirmed state is not reported as a pass' {
            $results = @(& $checkFile)
            $results[0].Finding | Should -Match 'reported as unassessed rather than a pass'
        }
    }

    Context 'Every Teams messaging policy carries the property and allows reporting' {
        BeforeEach {
            Mock Get-ReportSubmissionPolicy {
                [PSCustomObject]@{
                    ReportChatMessageEnabled                    = $true
                    ReportChatMessageToCustomizedAddressEnabled = $true
                }
            }
            Mock Get-CsTeamsMessagingPolicy {
                @(
                    [PSCustomObject]@{ Identity = 'Global';   AllowSecurityEndUserReporting = $true }
                    [PSCustomObject]@{ Identity = 'Tag:Sales'; AllowSecurityEndUserReporting = $true }
                )
            }
        }

        It 'Passes with the unchanged sentence once every policy is actually confirmed' {
            $results = @(& $checkFile)
            $results[0].Result  | Should -Be 'Pass'
            $results[0].Finding | Should -Match 'all Teams messaging policies allow users to report'
        }
    }
}
