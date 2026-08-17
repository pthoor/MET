BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"
    function Get-ExoPhishSimOverrideRule { [CmdletBinding()] param() }
    function Get-ExoSecOpsOverrideRule   { [CmdletBinding()] param() }
    function Get-ReportSubmissionPolicy  { [CmdletBinding()] param() }
    function Get-ReportSubmissionRule    { [CmdletBinding()] param() }
}

Describe 'MET-EXO014 Advanced Delivery Policy' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'EXO' 'MET-EXO014-AdvancedDeliveryPolicy.ps1'
    }

    Context 'no override rules' {
        BeforeAll {
            Mock Get-ExoPhishSimOverrideRule { @() }
            Mock Get-ExoSecOpsOverrideRule { @() }
        }

        It 'Returns Info and reports no overrides' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Info'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].Finding | Should -Match 'No enforceable Advanced Delivery'
        }
    }

    Context 'enabled override rule exists' {
        BeforeAll {
            Mock Get-ExoPhishSimOverrideRule {
                [PSCustomObject]@{ Name = 'KnowBe4Sim'; Mode = 'Enforce'; Domains = @('fabrikam.com') }
            }
            Mock Get-ExoSecOpsOverrideRule { @() }
        }

        It 'Returns Info and mentions the domain and count' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Info'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].Finding | Should -Match 'fabrikam.com'
            $results[0].Finding | Should -Match '1 enforceable'
            $results[0].AffectedObject | Should -Match '1 override rule'
        }
    }

    Context 'only disabled override rules exist' {
        BeforeAll {
            Mock Get-ExoPhishSimOverrideRule {
                [PSCustomObject]@{ Name = 'OldSim'; Mode = 'PendingDeletion' }
            }
            Mock Get-ExoSecOpsOverrideRule { @() }
        }

        It 'Returns Info and treats it as no overrides' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Info'
            $results[0].Finding | Should -Match 'No enforceable Advanced Delivery'
        }
    }

    Context 'SecOps override rule exists' {
        BeforeAll {
            Mock Get-ExoPhishSimOverrideRule { @() }
            Mock Get-ExoSecOpsOverrideRule {
                [PSCustomObject]@{ Name = 'SecOpsOverrideRule'; Mode = 'Enforce'; SentTo = @('secops@contoso.com') }
            }
        }

        It 'Returns Info and identifies the SecOps mailbox' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Info'
            $results[0].Finding | Should -Match 'SecOps mailbox: secops@contoso.com'
        }
    }

    Context 'phishing simulation cmdlet throws' {
        BeforeAll {
            Mock Get-ExoPhishSimOverrideRule { throw 'Access denied' }
            Mock Get-ExoSecOpsOverrideRule { @() }
        }

        It 'Returns Fail with Error populated' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Error | Should -Not -BeNullOrEmpty
        }

        It 'Recommendation references the known ErrorAction bug and documented permissions' {
            $results = & $checkFile
            $results[0].Recommendation | Should -Match 'ExchangeOnlineManagement bug'
            $results[0].Recommendation | Should -Match 'Global Reader'
        }
    }

    Context 'SecOps cmdlet throws' {
        BeforeAll {
            Mock Get-ExoPhishSimOverrideRule { @() }
            Mock Get-ExoSecOpsOverrideRule { throw 'SecOps unavailable' }
        }

        It 'Returns Fail with the SecOps error populated' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Error | Should -Match 'SecOps unavailable'
        }
    }

    Context 'SecOps rule SentTo count heuristic' {
        BeforeAll {
            Mock Get-ExoPhishSimOverrideRule { @() }
        }

        It 'Does not warn when SentTo has 2 mailboxes' {
            Mock Get-ExoSecOpsOverrideRule {
                [PSCustomObject]@{ Name = 'SecOpsOverrideRule'; Mode = 'Enforce'; SentTo = @('secops1@contoso.com', 'secops2@contoso.com') }
            }
            $results = & $checkFile
            $results | Where-Object { $_.Name -eq 'Advanced Delivery Policy - SecOps Mailbox Scope' } | Should -BeNullOrEmpty
        }

        It 'Warns when SentTo has more than 2 mailboxes' {
            Mock Get-ExoSecOpsOverrideRule {
                [PSCustomObject]@{ Name = 'SecOpsOverrideRule'; Mode = 'Enforce'; SentTo = @('secops1@contoso.com', 'secops2@contoso.com', 'secops3@contoso.com') }
            }
            $results = & $checkFile
            $scopeResult = $results | Where-Object { $_.Name -eq 'Advanced Delivery Policy - SecOps Mailbox Scope' }
            $scopeResult | Should -Not -BeNullOrEmpty
            $scopeResult.Result | Should -Be 'Warning'
            $scopeResult.Severity | Should -Be 'Medium'
            $scopeResult.Finding | Should -Match '3 mailboxes'
            $scopeResult.Finding | Should -Match 'MET-authored heuristic'
        }

        It 'Ignores inactive SecOps rules with a large SentTo list' {
            Mock Get-ExoSecOpsOverrideRule {
                [PSCustomObject]@{ Name = 'OldRule'; Mode = 'PendingDeletion'; SentTo = @('a@contoso.com', 'b@contoso.com', 'c@contoso.com') }
            }
            $results = & $checkFile
            $results | Where-Object { $_.Name -eq 'Advanced Delivery Policy - SecOps Mailbox Scope' } | Should -BeNullOrEmpty
        }
    }

    Context 'Phishing simulation SenderIpRanges heuristic' {
        BeforeAll {
            Mock Get-ExoSecOpsOverrideRule { @() }
        }

        It 'Does not warn for a /24 CIDR range' {
            Mock Get-ExoPhishSimOverrideRule {
                [PSCustomObject]@{ Name = 'KnowBe4Sim'; Mode = 'Enforce'; SenderIpRanges = @('192.168.1.0/24') }
            }
            $results = & $checkFile
            $results | Where-Object { $_.Name -eq 'Advanced Delivery Policy - Phishing Simulation Sender Scope' } | Should -BeNullOrEmpty
        }

        It 'Warns for a /8 CIDR range' {
            Mock Get-ExoPhishSimOverrideRule {
                [PSCustomObject]@{ Name = 'KnowBe4Sim'; Mode = 'Enforce'; SenderIpRanges = @('10.0.0.0/8') }
            }
            $results = & $checkFile
            $scopeResult = $results | Where-Object { $_.Name -eq 'Advanced Delivery Policy - Phishing Simulation Sender Scope' }
            $scopeResult | Should -Not -BeNullOrEmpty
            $scopeResult.Result | Should -Be 'Warning'
            $scopeResult.Severity | Should -Be 'Medium'
            $scopeResult.Finding | Should -Match '10.0.0.0/8'
        }

        It 'Warns for an explicit range spanning more than 65536 addresses' {
            Mock Get-ExoPhishSimOverrideRule {
                [PSCustomObject]@{ Name = 'KnowBe4Sim'; Mode = 'Enforce'; SenderIpRanges = @('10.0.0.1-10.2.0.1') }
            }
            $results = & $checkFile
            $scopeResult = $results | Where-Object { $_.Name -eq 'Advanced Delivery Policy - Phishing Simulation Sender Scope' }
            $scopeResult | Should -Not -BeNullOrEmpty
            $scopeResult.Result | Should -Be 'Warning'
        }

        It 'Does not warn for a single IP entry' {
            Mock Get-ExoPhishSimOverrideRule {
                [PSCustomObject]@{ Name = 'KnowBe4Sim'; Mode = 'Enforce'; SenderIpRanges = @('192.168.1.55') }
            }
            $results = & $checkFile
            $results | Where-Object { $_.Name -eq 'Advanced Delivery Policy - Phishing Simulation Sender Scope' } | Should -BeNullOrEmpty
        }
    }

    Context 'Reporting mailbox / SecOps cross-check' {
        BeforeAll {
            Mock Get-ExoPhishSimOverrideRule { @() }
        }

        It 'Warns when the reporting mailbox is not covered by any active SecOps rule' {
            Mock Get-ExoSecOpsOverrideRule {
                [PSCustomObject]@{ Name = 'SecOpsOverrideRule'; Mode = 'Enforce'; SentTo = @('other@contoso.com') }
            }
            Mock Get-ReportSubmissionPolicy { [PSCustomObject]@{ EnableReportToMicrosoft = $true; ReportJunkToCustomizedAddress = $false; ReportNotJunkToCustomizedAddress = $false; ReportPhishToCustomizedAddress = $false } }
            Mock Get-ReportSubmissionRule { [PSCustomObject]@{ SentTo = @('secops-reports@contoso.com') } }

            $results = & $checkFile
            $coverageResult = $results | Where-Object { $_.Name -eq 'Advanced Delivery Policy - Reporting Mailbox Coverage' }
            $coverageResult | Should -Not -BeNullOrEmpty
            $coverageResult.Result | Should -Be 'Warning'
            $coverageResult.Severity | Should -Be 'Medium'
            $coverageResult.Finding | Should -Match 'secops-reports@contoso.com'
            $coverageResult.ReferenceUrl | Should -Match 'submissions-user-reported-messages-custom-mailbox'
        }

        It 'Does not warn when the reporting mailbox is covered by an active SecOps rule (case-insensitive)' {
            Mock Get-ExoSecOpsOverrideRule {
                [PSCustomObject]@{ Name = 'SecOpsOverrideRule'; Mode = 'Enforce'; SentTo = @('SecOps-Reports@Contoso.com') }
            }
            Mock Get-ReportSubmissionPolicy { [PSCustomObject]@{ EnableReportToMicrosoft = $true; ReportJunkToCustomizedAddress = $false; ReportNotJunkToCustomizedAddress = $false; ReportPhishToCustomizedAddress = $false } }
            Mock Get-ReportSubmissionRule { [PSCustomObject]@{ SentTo = @('secops-reports@contoso.com') } }

            $results = & $checkFile
            $results | Where-Object { $_.Name -eq 'Advanced Delivery Policy - Reporting Mailbox Coverage' } | Should -BeNullOrEmpty
        }

        It 'Does not warn when no custom reporting mailbox is configured' {
            Mock Get-ExoSecOpsOverrideRule { @() }
            Mock Get-ReportSubmissionPolicy { [PSCustomObject]@{ EnableReportToMicrosoft = $false; ReportJunkToCustomizedAddress = $false; ReportNotJunkToCustomizedAddress = $false; ReportPhishToCustomizedAddress = $false } }
            Mock Get-ReportSubmissionRule { [PSCustomObject]@{ SentTo = $null } }

            $results = & $checkFile
            $results | Where-Object { $_.Name -eq 'Advanced Delivery Policy - Reporting Mailbox Coverage' } | Should -BeNullOrEmpty
        }

        It 'Does not fail the whole check when the submission cmdlets throw' {
            Mock Get-ExoSecOpsOverrideRule { @() }
            Mock Get-ReportSubmissionPolicy { throw 'Access denied' }

            $results = & $checkFile
            $results[0].Result | Should -Be 'Info'
            $results | Where-Object { $_.Name -eq 'Advanced Delivery Policy - Reporting Mailbox Coverage' } | Should -BeNullOrEmpty
        }

        It 'Warns about a stale per-flow policy address even when the rule mailbox is covered' {
            Mock Get-ExoSecOpsOverrideRule {
                [PSCustomObject]@{ Name = 'SecOpsOverrideRule'; Mode = 'Enforce'; SentTo = @('secops-reports@contoso.com') }
            }
            Mock Get-ReportSubmissionPolicy {
                [PSCustomObject]@{
                    EnableReportToMicrosoft = $true
                    ReportJunkToCustomizedAddress = $true; ReportJunkAddresses = @('old-secops@contoso.com')
                    ReportNotJunkToCustomizedAddress = $true; ReportNotJunkAddresses = @('secops-reports@contoso.com')
                    ReportPhishToCustomizedAddress = $true; ReportPhishAddresses = @('secops-reports@contoso.com')
                }
            }
            Mock Get-ReportSubmissionRule { [PSCustomObject]@{ SentTo = @('secops-reports@contoso.com') } }

            $results = & $checkFile
            $coverageResult = $results | Where-Object { $_.Name -eq 'Advanced Delivery Policy - Reporting Mailbox Coverage' }
            $coverageResult | Should -Not -BeNullOrEmpty
            $coverageResult.Result | Should -Be 'Warning'
            $coverageResult.Finding | Should -Match 'old-secops@contoso.com'
            $coverageResult.Finding | Should -Match 'Junk reports'
        }

        It 'Notes as Info when a SecOps mailbox is not tied to any reporting flow' {
            Mock Get-ExoSecOpsOverrideRule {
                [PSCustomObject]@{ Name = 'SecOpsOverrideRule'; Mode = 'Enforce'; SentTo = @('pierre@thoor.tech', 'adam@thoorsec.onmicrosoft.com') }
            }
            Mock Get-ReportSubmissionPolicy { [PSCustomObject]@{ EnableReportToMicrosoft = $true; ReportJunkToCustomizedAddress = $false; ReportNotJunkToCustomizedAddress = $false; ReportPhishToCustomizedAddress = $false } }
            Mock Get-ReportSubmissionRule { [PSCustomObject]@{ SentTo = @('pierre@thoor.tech') } }

            $results = & $checkFile
            $purposeResult = $results | Where-Object { $_.Name -eq 'Advanced Delivery Policy - SecOps Mailbox Purpose' }
            $purposeResult | Should -Not -BeNullOrEmpty
            $purposeResult.Result | Should -Be 'Info'
            $purposeResult.Severity | Should -Be 'Low'
            $purposeResult.Finding | Should -Match 'adam@thoorsec.onmicrosoft.com'
            $purposeResult.Finding | Should -Not -Match 'pierre@thoor.tech'
        }

        It 'Does not note SecOps Mailbox Purpose when every SecOps mailbox is tied to reporting' {
            Mock Get-ExoSecOpsOverrideRule {
                [PSCustomObject]@{ Name = 'SecOpsOverrideRule'; Mode = 'Enforce'; SentTo = @('pierre@thoor.tech') }
            }
            Mock Get-ReportSubmissionPolicy { [PSCustomObject]@{ EnableReportToMicrosoft = $true; ReportJunkToCustomizedAddress = $false; ReportNotJunkToCustomizedAddress = $false; ReportPhishToCustomizedAddress = $false } }
            Mock Get-ReportSubmissionRule { [PSCustomObject]@{ SentTo = @('pierre@thoor.tech') } }

            $results = & $checkFile
            $results | Where-Object { $_.Name -eq 'Advanced Delivery Policy - SecOps Mailbox Purpose' } | Should -BeNullOrEmpty
        }
    }
}
