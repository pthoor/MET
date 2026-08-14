BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"
    . "$root/Private/Resolve-METPresetPolicy.ps1"
    . "$root/Private/Resolve-METCoverageMatrix.ps1"
    . "$root/Private/Expand-METRuleRecipients.ps1"
    . "$root/Private/Expand-METGroupMembership.ps1"
    . "$root/Private/Get-METRuleScope.ps1"
    . "$root/Private/Get-METAssessableMailboxes.ps1"

    function Get-EXOMailbox              { [CmdletBinding()] param([string]$ResultSize,[string]$PropertySets) }
    function Get-EOPProtectionPolicyRule { [CmdletBinding()] param([string]$Identity) }
    function Get-ATPProtectionPolicyRule { [CmdletBinding()] param([string]$Identity) }
    function Get-HostedContentFilterRule { [CmdletBinding()] param() }
    function Get-MalwareFilterRule       { [CmdletBinding()] param() }
    function Get-SafeLinksRule           { [CmdletBinding()] param() }
    function Get-SafeAttachmentRule      { [CmdletBinding()] param() }
    function Get-AntiPhishRule           { [CmdletBinding()] param() }
}

Describe 'MET-MDO013 Policy Precedence Conflicts' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'MDO' 'MET-MDO013-PolicyPrecedenceConflicts.ps1'
        $METContext = @{}
    }

    Context 'No mailboxes exist' {
        BeforeAll {
            Mock Get-EXOMailbox { @() }
        }

        It 'Returns NotApplicable' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'NotApplicable'
            $results[0].CheckId | Should -Be 'MET-MDO013'
        }
    }

    Context 'No preset policies enabled, one custom Safe Links rule covering some mailboxes' {
        BeforeAll {
            Mock Get-EXOMailbox {
                @('alice@contoso.com', 'bob@contoso.com', 'carol@contoso.com') |
                    ForEach-Object { [PSCustomObject]@{ PrimarySmtpAddress = $_ } }
            }
            Mock Get-EOPProtectionPolicyRule { @() }
            Mock Get-ATPProtectionPolicyRule { @() }
            Mock Get-HostedContentFilterRule { @() }
            Mock Get-AntiPhishRule           { @() }
            Mock Get-SafeLinksRule {
                @(
                    [PSCustomObject]@{
                        Name           = 'Custom Safe Links - Sales'
                        State          = 'Enabled'
                        Priority       = 0
                        SentTo         = @('alice@contoso.com')
                        SentToMemberOf = $null
                    }
                )
            }
        }

        It 'Returns Pass - nothing to shadow against' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
        }
    }

    Context 'Standard preset (ATP stack) covers all mailboxes, plus a custom Anti-Phish rule targets a subset' {
        BeforeAll {
            Mock Get-EXOMailbox {
                @('alice@contoso.com', 'bob@contoso.com', 'carol@contoso.com') |
                    ForEach-Object { [PSCustomObject]@{ PrimarySmtpAddress = $_ } }
            }
            Mock Get-EOPProtectionPolicyRule { @() }
            Mock Get-ATPProtectionPolicyRule {
                [PSCustomObject]@{
                    Name           = 'Standard Preset Security Policy'
                    State          = 'Enabled'
                    Priority       = 0
                    SentTo         = $null
                    SentToMemberOf = $null
                }
            }
            Mock Get-HostedContentFilterRule { @() }
            Mock Get-SafeLinksRule           { @() }
            Mock Get-AntiPhishRule {
                @(
                    [PSCustomObject]@{
                        Name           = 'Custom Anti-Phish - VIPs'
                        State          = 'Enabled'
                        Priority       = 0
                        SentTo         = @('alice@contoso.com', 'bob@contoso.com')
                        SentToMemberOf = $null
                    }
                )
            }
        }

        It 'Returns Warning' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Severity | Should -Be 'High'
        }

        It 'Finding mentions Anti-Phish, the rule name, and the shadowed count' {
            $results = & $checkFile
            $results[0].Finding | Should -Match 'Anti-Phish'
            $results[0].Finding | Should -Match 'Custom Anti-Phish - VIPs'
            $results[0].Finding | Should -Match '2 of them'
        }
    }

    Context 'Custom Safe Links rule targets mailboxes not covered by any preset' {
        BeforeAll {
            Mock Get-EXOMailbox {
                @('alice@contoso.com', 'bob@contoso.com', 'carol@contoso.com') |
                    ForEach-Object { [PSCustomObject]@{ PrimarySmtpAddress = $_ } }
            }
            Mock Get-EOPProtectionPolicyRule { @() }
            Mock Get-ATPProtectionPolicyRule {
                [PSCustomObject]@{
                    Name           = 'Standard Preset Security Policy'
                    State          = 'Enabled'
                    Priority       = 0
                    SentTo         = @('carol@contoso.com')
                    SentToMemberOf = $null
                }
            }
            Mock Get-HostedContentFilterRule { @() }
            Mock Get-AntiPhishRule           { @() }
            Mock Get-SafeLinksRule {
                @(
                    [PSCustomObject]@{
                        Name           = 'Custom Safe Links - Sales'
                        State          = 'Enabled'
                        Priority       = 0
                        SentTo         = @('alice@contoso.com', 'bob@contoso.com')
                        SentToMemberOf = $null
                    }
                )
            }
        }

        It 'Returns Pass - no overlap between preset and custom rule targets' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
        }
    }

    Context 'Standard preset covers a custom Safe Attachments rule' {
        BeforeAll {
            Mock Get-EXOMailbox {
                [PSCustomObject]@{ PrimarySmtpAddress = 'alice@contoso.com' }
            }
            Mock Get-EOPProtectionPolicyRule { @() }
            Mock Get-ATPProtectionPolicyRule {
                [PSCustomObject]@{
                    Name = 'Standard Preset Security Policy'; State = 'Enabled'; SentTo = @('alice@contoso.com')
                }
            }
            Mock Get-HostedContentFilterRule { @() }
            Mock Get-MalwareFilterRule { @() }
            Mock Get-SafeLinksRule { @() }
            Mock Get-AntiPhishRule { @() }
            Mock Get-SafeAttachmentRule {
                [PSCustomObject]@{
                    Name = 'Custom Safe Attachments'; State = 'Enabled'; Priority = 0; SentTo = @('alice@contoso.com')
                }
            }
        }

        It 'Returns Warning for the omitted policy family' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'Safe Attachments'
        }
    }

    Context 'Standard preset covers a custom anti-malware rule' {
        BeforeAll {
            Mock Get-EXOMailbox {
                [PSCustomObject]@{ PrimarySmtpAddress = 'alice@contoso.com' }
            }
            Mock Get-EOPProtectionPolicyRule {
                [PSCustomObject]@{
                    Name = 'Standard Preset Security Policy'; State = 'Enabled'; SentTo = @('alice@contoso.com')
                }
            }
            Mock Get-ATPProtectionPolicyRule { @() }
            Mock Get-HostedContentFilterRule { @() }
            Mock Get-SafeLinksRule { @() }
            Mock Get-SafeAttachmentRule { @() }
            Mock Get-AntiPhishRule { @() }
            Mock Get-MalwareFilterRule {
                [PSCustomObject]@{
                    Name = 'Custom Malware'; State = 'Enabled'; Priority = 0; SentTo = @('alice@contoso.com')
                }
            }
        }

        It 'Returns Warning for the omitted policy family' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'Anti-Malware'
        }
    }

    Context 'A required policy getter fails' {
        BeforeAll {
            Mock Get-EXOMailbox {
                [PSCustomObject]@{ PrimarySmtpAddress = 'alice@contoso.com' }
            }
            Mock Get-EOPProtectionPolicyRule { @() }
            Mock Get-ATPProtectionPolicyRule { @() }
            Mock Get-HostedContentFilterRule { throw 'Transient Exchange failure' }
            Mock Get-MalwareFilterRule { @() }
            Mock Get-SafeLinksRule { @() }
            Mock Get-SafeAttachmentRule { @() }
            Mock Get-AntiPhishRule { @() }
        }

        It 'Returns Fail with Error instead of Pass' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Error | Should -Match 'Transient Exchange failure'
        }
    }

    Context 'Get-EXOMailbox throws' {
        BeforeAll {
            Mock Get-EXOMailbox { throw 'Unauthorized' }
        }

        It 'Returns Fail with Error populated' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Error | Should -Not -BeNullOrEmpty
        }
    }
}
