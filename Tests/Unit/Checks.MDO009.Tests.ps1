BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"
    . "$root/Private/Get-METRuleScope.ps1"
    . "$root/Private/Get-METAssessableMailboxes.ps1"
    . "$root/Private/Expand-METGroupMembership.ps1"
    . "$root/Private/Expand-METRuleRecipients.ps1"
    . "$root/Private/Resolve-METEffectivePolicy.ps1"
    . "$root/Private/New-METEffectivePolicyCoverageResult.ps1"
    . "$root/Private/Get-METPolicyOrderingObservations.ps1"

    function Get-EXOMailbox                { [CmdletBinding()] param([string]$ResultSize,[string]$PropertySets,[string[]]$Properties,[string]$Filter) }
    function Get-HostedContentFilterRule   { [CmdletBinding()] param() }
    function Get-HostedContentFilterPolicy { [CmdletBinding()] param() }
    function Get-ATPProtectionPolicyRule   { [CmdletBinding()] param([string]$Identity) }
    function Get-EOPProtectionPolicyRule   { [CmdletBinding()] param([string]$Identity) }
}

Describe 'MET-MDO009 ZAP' {

    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'MDO' 'MET-MDO009-ZAP.ps1'
        $script:METContext = $null
        Mock Get-EXOMailbox { [PSCustomObject]@{ PrimarySmtpAddress = 'alice@contoso.com'; RecipientTypeDetails = 'UserMailbox' } }
        Mock Get-ATPProtectionPolicyRule { @() }
        Mock Get-EOPProtectionPolicyRule { @() }
    }

    Context 'ZAP fully enabled' {
        BeforeAll {
            Mock Get-HostedContentFilterRule   { @() }
            Mock Get-HostedContentFilterPolicy {
                [PSCustomObject]@{
                    Name            = 'Default'
                    IsDefault       = $true
                    ZapEnabled      = $true
                    SpamZapEnabled  = $true
                    PhishZapEnabled = $true
                }
            }
        }
        It 'Returns Pass' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
        }
    }

    Context 'Legacy aggregate ZAP flag disabled' {
        BeforeAll {
            Mock Get-HostedContentFilterRule   { @() }
            Mock Get-HostedContentFilterPolicy {
                [PSCustomObject]@{
                    Name            = 'Default'
                    IsDefault       = $true
                    ZapEnabled      = $false
                    SpamZapEnabled  = $true
                    PhishZapEnabled = $true
                }
            }
        }
        It 'Returns Pass when the documented spam and phish ZAP settings are enabled' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
        }
    }

    Context 'Phish ZAP disabled' {
        BeforeAll {
            Mock Get-HostedContentFilterRule   { @() }
            Mock Get-HostedContentFilterPolicy {
                [PSCustomObject]@{
                    Name            = 'Default'
                    IsDefault       = $true
                    ZapEnabled      = $true
                    SpamZapEnabled  = $true
                    PhishZapEnabled = $false
                }
            }
        }
        It 'Returns Fail and mentions phishing' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Finding | Should -Match 'phish'
        }
    }

    # An anti-spam policy object that returns neither ZAP property used to leave both -not
    # tests true, indistinguishable from both settings being switched off. The check now
    # branches on absence before the falsy test, so the two are distinguished.
    Context 'The effective anti-spam policy omits SpamZapEnabled and PhishZapEnabled' {
        BeforeAll {
            Mock Get-HostedContentFilterRule   { @() }
            Mock Get-HostedContentFilterPolicy {
                [PSCustomObject]@{ Name = 'Default'; IsDefault = $true }
            }
        }

        It 'Does not return Pass on settings it never observed' {
            $results = & $checkFile
            $results[0].Result | Should -Not -Be 'Pass'
        }

        It 'States both ZAP properties were not returned rather than asserting they are disabled' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Finding | Should -Match 'SpamZapEnabled was not returned'
            $results[0].Finding | Should -Match 'PhishZapEnabled was not returned'
            $results[0].Finding | Should -Not -Match 'ZAP for spam is disabled'
            $results[0].Finding | Should -Not -Match 'ZAP for phishing is disabled'
        }
    }

    # Both ZAP properties are read with -not, so the secure value is $true and the issue
    # text is the negative. Reading either as "ZAP is off" inverts the verdict, so both
    # senses are pinned for both properties, and each is pinned independently so one
    # cannot silently stand in for the other.
    Context 'Inverted-sense regression guard' {
        It 'Fails only when the ZAP settings are false and passes only when they are true' {
            Mock Get-HostedContentFilterRule   { @() }
            Mock Get-HostedContentFilterPolicy {
                [PSCustomObject]@{ Name = 'Default'; IsDefault = $true; SpamZapEnabled = $true; PhishZapEnabled = $true }
            }
            $secure = (& $checkFile)[0]
            $secure.Result | Should -Be 'Pass'
            $secure.Finding | Should -Not -Match 'ZAP for spam is disabled'
            $secure.Finding | Should -Not -Match 'ZAP for phishing is disabled'

            Mock Get-HostedContentFilterPolicy {
                [PSCustomObject]@{ Name = 'Default'; IsDefault = $true; SpamZapEnabled = $false; PhishZapEnabled = $false }
            }
            $insecure = (& $checkFile)[0]
            $insecure.Result | Should -Be 'Fail'
            $insecure.Finding | Should -Match 'ZAP for spam is disabled'
            $insecure.Finding | Should -Match 'ZAP for phishing is disabled'
        }

        It 'Keeps the spam and phish settings independent' {
            Mock Get-HostedContentFilterRule   { @() }
            Mock Get-HostedContentFilterPolicy {
                [PSCustomObject]@{ Name = 'Default'; IsDefault = $true; SpamZapEnabled = $false; PhishZapEnabled = $true }
            }
            $spamOnly = (& $checkFile)[0]
            $spamOnly.Finding | Should -Match 'ZAP for spam is disabled'
            $spamOnly.Finding | Should -Not -Match 'ZAP for phishing is disabled'

            Mock Get-HostedContentFilterPolicy {
                [PSCustomObject]@{ Name = 'Default'; IsDefault = $true; SpamZapEnabled = $true; PhishZapEnabled = $false }
            }
            $phishOnly = (& $checkFile)[0]
            $phishOnly.Finding | Should -Match 'ZAP for phishing is disabled'
            $phishOnly.Finding | Should -Not -Match 'ZAP for spam is disabled'
        }
    }
}
