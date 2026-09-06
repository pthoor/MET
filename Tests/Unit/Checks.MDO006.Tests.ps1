BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Expand-METRuleRecipients.ps1"
    . "$root/Private/Resolve-METEffectivePolicy.ps1"
    . "$root/Private/New-METEffectivePolicyCoverageResult.ps1"
    . "$root/Private/Get-METPolicyOrderingObservations.ps1"

    function Get-HostedContentFilterRule   { [CmdletBinding()] param() }
    function Get-HostedContentFilterPolicy { [CmdletBinding()] param() }
    function Get-EOPProtectionPolicyRule   { [CmdletBinding()] param([string]$Identity) }

    $checkFile = Join-Path $root 'Checks' 'MDO' 'MET-MDO006-AntiSpamInbound.ps1'

    function New-METInboundCatchAllRule {
        param([string] $Name = 'Default')
        $rule = [PSCustomObject]@{ Name = $Name; HostedContentFilterPolicy = $Name; State = 'Enabled'; Priority = 0 }
        $rule | Add-Member SentTo $null
        $rule | Add-Member SentToMemberOf $null
        $rule | Add-Member RecipientDomainIs $null
        $rule | Add-Member ExceptIfSentTo $null
        $rule | Add-Member ExceptIfSentToMemberOf $null
        $rule | Add-Member ExceptIfRecipientDomainIs $null
        $rule
    }
}

Describe 'MET-MDO006 Anti-Spam Inbound - BulkThreshold assessment' {

    BeforeEach {
        $script:METContext = @{ AllMailboxes = @('a@contoso.com') }
        Mock Get-HostedContentFilterRule { @(New-METInboundCatchAllRule) }
        Mock Get-EOPProtectionPolicyRule { @() }
    }

    Context 'An otherwise compliant policy omits the BulkThreshold property' {
        BeforeAll {
            Mock Get-HostedContentFilterPolicy {
                [PSCustomObject]@{
                    Name = 'Default'; IsDefault = $true; SpamAction = 'MoveToJmf'; HighConfidenceSpamAction = 'Quarantine'
                    PhishSpamAction = 'Quarantine'; HighConfidencePhishAction = 'Quarantine'
                    HighConfidencePhishQuarantineTag = 'AdminOnlyAccessPolicy'; AllowedSenders = @(); AllowedSenderDomains = @()
                }
            }
        }

        It 'Does not report the recipient as fully protected on an unreturned threshold' {
            $result = & $checkFile
            $result.Result  | Should -Not -Be 'Pass'
            $result.Finding | Should -Match 'BulkThreshold was not returned by Get-HostedContentFilterPolicy'
        }
    }

    Context 'An otherwise compliant policy has BulkThreshold present but explicitly $null' {
        BeforeAll {
            Mock Get-HostedContentFilterPolicy {
                [PSCustomObject]@{
                    Name = 'Default'; IsDefault = $true; SpamAction = 'MoveToJmf'; HighConfidenceSpamAction = 'Quarantine'
                    PhishSpamAction = 'Quarantine'; HighConfidencePhishAction = 'Quarantine'; BulkThreshold = $null
                    HighConfidencePhishQuarantineTag = 'AdminOnlyAccessPolicy'; AllowedSenders = @(); AllowedSenderDomains = @()
                }
            }
        }

        It 'Treats a present-but-null BulkThreshold the same as an absent one' {
            $result = & $checkFile
            $result.Result  | Should -Not -Be 'Pass'
            $result.Finding | Should -Match 'BulkThreshold was not returned by Get-HostedContentFilterPolicy'
        }
    }

    Context 'BulkThreshold exceeds the recommended maximum' {
        BeforeAll {
            Mock Get-HostedContentFilterPolicy {
                [PSCustomObject]@{
                    Name = 'Default'; IsDefault = $true; SpamAction = 'MoveToJmf'; HighConfidenceSpamAction = 'Quarantine'
                    PhishSpamAction = 'Quarantine'; HighConfidencePhishAction = 'Quarantine'; BulkThreshold = 9
                    HighConfidencePhishQuarantineTag = 'AdminOnlyAccessPolicy'; AllowedSenders = @(); AllowedSenderDomains = @()
                }
            }
        }

        It 'Keeps the existing over-threshold sentence unchanged' {
            $result = & $checkFile
            $result.Result  | Should -Be 'Fail'
            $result.Finding | Should -Match 'Bulk complaint level threshold is 9 - Standard recommends 6 or lower'
        }
    }

    Context 'BulkThreshold is at the recommended maximum' {
        BeforeAll {
            Mock Get-HostedContentFilterPolicy {
                [PSCustomObject]@{
                    Name = 'Default'; IsDefault = $true; SpamAction = 'MoveToJmf'; HighConfidenceSpamAction = 'Quarantine'
                    PhishSpamAction = 'Quarantine'; HighConfidencePhishAction = 'Quarantine'; BulkThreshold = 6
                    HighConfidencePhishQuarantineTag = 'AdminOnlyAccessPolicy'; AllowedSenders = @(); AllowedSenderDomains = @()
                }
            }
        }

        It 'Keeps the existing compliant behaviour unchanged' {
            $result = & $checkFile
            $result.Result  | Should -Be 'Pass'
            $result.Finding | Should -Not -Match 'Bulk complaint level threshold'
            $result.Finding | Should -Not -Match 'BulkThreshold was not returned'
        }
    }
}
