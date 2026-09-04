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

        # Pins current behaviour, which is wrong: the messaging-policy filter requires
        # AllowSecurityEndUserReporting to be present and explicitly $false, so a policy
        # that omits the property is treated as compliant and the check goes on to claim
        # "all Teams messaging policies allow users to report security concerns" - a
        # state it never observed. Per the repo's own rule an absent property must not
        # yield Pass. Left pinned so the defect is visible and cannot change unnoticed.
        It 'Currently returns Pass and claims every policy allows reporting' {
            $results = @(& $checkFile)
            $results[0].Result  | Should -Be 'Pass'
            $results[0].Finding | Should -Match 'all Teams messaging policies allow users to report'
        }
    }
}
