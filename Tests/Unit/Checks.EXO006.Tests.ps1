BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"

    function Get-ReportSubmissionPolicy { [CmdletBinding()] param() }
    function Get-ReportSubmissionRule   { [CmdletBinding()] param() }
}

Describe 'MET-EXO006 Submission Policy' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'EXO' 'MET-EXO006-SubmissionPolicy.ps1'
    }

    Context 'Reporting to Microsoft enabled with submission mailbox' {
        BeforeAll {
            Mock Get-ReportSubmissionPolicy {
                [PSCustomObject]@{ EnableReportToMicrosoft = $true; EnableUserEmailNotification = $true }
            }
            Mock Get-ReportSubmissionRule {
                [PSCustomObject]@{ SentTo = 'secops@contoso.com' }
            }
        }
        It 'Returns Pass' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
        }
    }

    # EnableThirdPartyAddress is explicit here (rather than left absent) so this context
    # exercises the confirmed-disabled branch rather than the not-returned branch added
    # below for the same overall Fail verdict.
    Context 'Reporting to Microsoft disabled' {
        BeforeAll {
            Mock Get-ReportSubmissionPolicy {
                [PSCustomObject]@{ EnableReportToMicrosoft = $false; EnableThirdPartyAddress = $false; EnableUserEmailNotification = $true }
            }
            Mock Get-ReportSubmissionRule { $null }
        }
        It 'Returns Fail' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
        }

        It 'States reporting is completely disabled rather than that a property was not returned' {
            $results = & $checkFile
            $results[0].Finding | Should -Match 'completely disabled'
            $results[0].Finding | Should -Not -Match 'not returned'
        }
    }

    Context 'No submission mailbox configured' {
        BeforeAll {
            Mock Get-ReportSubmissionPolicy {
                [PSCustomObject]@{ EnableReportToMicrosoft = $true; EnableUserEmailNotification = $true }
            }
            Mock Get-ReportSubmissionRule { $null }
        }
        It 'Returns Warning and mentions mailbox' {
            $results = & $checkFile
            $mailboxResult = $results | Where-Object { $_.Name -match 'SecOps Mailbox' }
            $mailboxResult | Should -Not -BeNullOrEmpty
            $mailboxResult.Result | Should -Be 'Warning'
            $mailboxResult.Finding | Should -Match 'mailbox'
        }
    }

    Context 'Rule and policy addresses agree' {
        BeforeAll {
            Mock Get-ReportSubmissionPolicy {
                [PSCustomObject]@{
                    EnableReportToMicrosoft = $true; EnableUserEmailNotification = $true
                    ReportJunkToCustomizedAddress = $true; ReportNotJunkToCustomizedAddress = $true; ReportPhishToCustomizedAddress = $true
                    ReportJunkAddresses = 'secops@contoso.com'; ReportNotJunkAddresses = 'secops@contoso.com'; ReportPhishAddresses = 'secops@contoso.com'
                }
            }
            Mock Get-ReportSubmissionRule { [PSCustomObject]@{ SentTo = 'secops@contoso.com' } }
        }
        It 'Returns Pass for address consistency' {
            $results = & $checkFile
            $consistencyResult = $results | Where-Object { $_.Name -match 'Mailbox Address Consistency' }
            $consistencyResult | Should -Not -BeNullOrEmpty
            $consistencyResult.Result | Should -Be 'Pass'
        }
    }

    Context 'Rule and policy addresses drift' {
        BeforeAll {
            Mock Get-ReportSubmissionPolicy {
                [PSCustomObject]@{
                    EnableReportToMicrosoft = $true; EnableUserEmailNotification = $true
                    ReportJunkToCustomizedAddress = $true; ReportNotJunkToCustomizedAddress = $true; ReportPhishToCustomizedAddress = $true
                    ReportJunkAddresses = 'old-secops@contoso.com'; ReportNotJunkAddresses = 'secops@contoso.com'; ReportPhishAddresses = 'secops@contoso.com'
                }
            }
            Mock Get-ReportSubmissionRule { [PSCustomObject]@{ SentTo = 'secops@contoso.com' } }
        }
        It 'Returns Warning identifying the mismatched report type and stale address' {
            $results = & $checkFile
            $consistencyResult = $results | Where-Object { $_.Name -match 'Mailbox Address Consistency' }
            $consistencyResult | Should -Not -BeNullOrEmpty
            $consistencyResult.Result | Should -Be 'Warning'
            $consistencyResult.Finding | Should -Match 'Junk reports go to'
            $consistencyResult.Finding | Should -Match 'old-secops@contoso.com'
        }
    }

    Context 'Rule routes reports to more than one address' {
        BeforeAll {
            Mock Get-ReportSubmissionPolicy {
                [PSCustomObject]@{
                    EnableReportToMicrosoft = $true; EnableUserEmailNotification = $true
                    ReportJunkToCustomizedAddress = $true; ReportNotJunkToCustomizedAddress = $true; ReportPhishToCustomizedAddress = $true
                    ReportJunkAddresses = 'secops@contoso.com'; ReportNotJunkAddresses = 'secops@contoso.com'; ReportPhishAddresses = 'secops@contoso.com'
                }
            }
            Mock Get-ReportSubmissionRule { [PSCustomObject]@{ SentTo = @('secops@contoso.com', 'soc@contoso.com') } }
        }
        It 'Never renders the addresses space-joined' {
            $results = & $checkFile
            foreach ($result in $results) {
                $result.AffectedObject | Should -Not -Match 'secops@contoso\.com soc@contoso\.com'
                $result.Finding | Should -Not -Match 'secops@contoso\.com soc@contoso\.com'
            }
        }
        It 'Compares the policy addresses against the first address only' {
            $results = & $checkFile
            $consistencyResult = $results | Where-Object { $_.Name -match 'Mailbox Address Consistency' }
            $consistencyResult | Should -Not -BeNullOrEmpty
            $consistencyResult.Result | Should -Be 'Pass'
        }
        It 'Names the first address as the SecOps mailbox and surfaces the additional one' {
            $results = & $checkFile
            $mailboxResult = $results | Where-Object { $_.Name -match 'SecOps Mailbox' }
            $mailboxResult | Should -Not -BeNullOrEmpty
            $mailboxResult.AffectedObject | Should -Be 'Report Submission Policy (secops@contoso.com)'
            $mailboxResult.Finding | Should -Match "'secops@contoso\.com'"
            $mailboxResult.Finding | Should -Match 'soc@contoso\.com'
        }
    }

    Context 'Rule routes to more than one address and the policy has drifted' {
        BeforeAll {
            Mock Get-ReportSubmissionPolicy {
                [PSCustomObject]@{
                    EnableReportToMicrosoft = $true; EnableUserEmailNotification = $true
                    ReportJunkToCustomizedAddress = $true; ReportNotJunkToCustomizedAddress = $true; ReportPhishToCustomizedAddress = $true
                    ReportJunkAddresses = 'old-secops@contoso.com'; ReportNotJunkAddresses = 'secops@contoso.com'; ReportPhishAddresses = 'secops@contoso.com'
                }
            }
            Mock Get-ReportSubmissionRule { [PSCustomObject]@{ SentTo = @('secops@contoso.com', 'soc@contoso.com') } }
        }
        It 'Still detects the drift against the first address' {
            $results = & $checkFile
            $consistencyResult = $results | Where-Object { $_.Name -match 'Mailbox Address Consistency' }
            $consistencyResult | Should -Not -BeNullOrEmpty
            $consistencyResult.Result | Should -Be 'Warning'
            $consistencyResult.Finding | Should -Match 'Junk reports go to'
            $consistencyResult.Finding | Should -Match 'old-secops@contoso.com'
            $consistencyResult.Finding | Should -Not -Match 'secops@contoso\.com soc@contoso\.com'
        }
    }

    # A report submission policy object that returns none of the reporting flags used to
    # leave every -eq $true comparison false, indistinguishable from a tenant that has
    # genuinely switched reporting off. The check now branches on whether either flag was
    # actually returned before concluding reporting is disabled.
    Context 'The report submission policy omits every reporting property' {
        BeforeAll {
            Mock Get-ReportSubmissionPolicy {
                [PSCustomObject]@{ Identity = 'DefaultReportSubmissionPolicy' }
            }
            Mock Get-ReportSubmissionRule { $null }
        }

        It 'Does not return Pass on a reporting configuration it never observed' {
            $results = @(& $checkFile)
            ($results | Where-Object { $_.Result -eq 'Pass' }) | Should -BeNullOrEmpty
        }

        It 'States the properties were not returned rather than that reporting is completely disabled' {
            $results = @(& $checkFile)
            $buttonResult = $results | Where-Object { $_.Name -match 'Report Button' }
            $buttonResult | Should -Not -BeNullOrEmpty
            $buttonResult.Result | Should -Be 'Fail'
            $buttonResult.AffectedObject | Should -Be 'Report Submission Policy'
            $buttonResult.Finding | Should -Match 'not returned'
            $buttonResult.Finding | Should -Match 'EnableReportToMicrosoft'
            $buttonResult.Finding | Should -Match 'EnableThirdPartyAddress'
            $buttonResult.Finding | Should -Not -Match 'completely disabled'
        }
    }

    # Only one of the two properties is absent - the Finding must name only that one.
    Context 'Only EnableReportToMicrosoft is absent' {
        BeforeAll {
            Mock Get-ReportSubmissionPolicy {
                [PSCustomObject]@{ EnableThirdPartyAddress = $false }
            }
            Mock Get-ReportSubmissionRule { $null }
        }

        It 'Names only the absent property' {
            $results = @(& $checkFile)
            $buttonResult = $results | Where-Object { $_.Name -match 'Report Button' }
            $buttonResult.Result | Should -Be 'Fail'
            $buttonResult.Finding | Should -Match 'EnableReportToMicrosoft'
            $buttonResult.Finding | Should -Not -Match 'EnableThirdPartyAddress was not returned'
        }
    }

    # Mutation verification: the confirmed-disabled sentence and the not-returned sentence
    # must differ even though both are Fail.
    Context 'Both flags absent vs. both flags present and false' {
        It 'Produces different Findings for the same Fail verdict' {
            Mock Get-ReportSubmissionPolicy { [PSCustomObject]@{ Identity = 'DefaultReportSubmissionPolicy' } }
            Mock Get-ReportSubmissionRule { $null }
            $absent = @(& $checkFile) | Where-Object { $_.Name -match 'Report Button' }
            $absent.Result | Should -Be 'Fail'
            $absent.Finding | Should -Match 'not returned'
            $absent.Finding | Should -Not -Match 'completely disabled'

            Mock Get-ReportSubmissionPolicy { [PSCustomObject]@{ EnableReportToMicrosoft = $false; EnableThirdPartyAddress = $false } }
            $present = @(& $checkFile) | Where-Object { $_.Name -match 'Report Button' }
            $present.Result | Should -Be 'Fail'
            $present.Finding | Should -Match 'completely disabled'
            $present.Finding | Should -Not -Match 'not returned'
        }
    }
}
