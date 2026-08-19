BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METPresetSecurityPolicyTier.ps1"
    . "$root/Private/Test-METIsPresetSecurityPolicyName.ps1"

    function Get-QuarantinePolicy { [CmdletBinding()] param() }
    function Get-HostedContentFilterPolicy { [CmdletBinding()] param() }
    function Get-MalwareFilterPolicy { [CmdletBinding()] param() }
    function Get-AntiPhishPolicy { [CmdletBinding()] param() }
    function Get-SafeAttachmentPolicy { [CmdletBinding()] param() }

    function New-METQuarantinePolicy {
        param([string] $Name, [bool] $PermissionToRelease)
        [PSCustomObject]@{
            Name                        = $Name
            EndUserQuarantinePermissions = [PSCustomObject]@{ PermissionToRelease = $PermissionToRelease }
        }
    }
}

Describe 'MET-EXO009 Quarantine Policy Verdict Alignment' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'EXO' 'MET-EXO009-QuarantinePolicyVerdictAlignment.ps1'
    }

    Context 'Strict preset anti-phish policy with full-access impersonation/spoof tags' {
        BeforeAll {
            Mock Get-QuarantinePolicy {
                @(
                    New-METQuarantinePolicy -Name 'AdminOnlyAccessPolicy' -PermissionToRelease $false
                    New-METQuarantinePolicy -Name 'DefaultFullAccessWithNotificationPolicy' -PermissionToRelease $true
                )
            }
            Mock Get-HostedContentFilterPolicy { @() }
            Mock Get-MalwareFilterPolicy { @() }
            Mock Get-AntiPhishPolicy {
                @(
                    [PSCustomObject]@{
                        Name                              = 'Strict Preset Security Policy1707729536596'
                        TargetedUserQuarantineTag          = 'DefaultFullAccessWithNotificationPolicy'
                        TargetedDomainQuarantineTag        = 'DefaultFullAccessWithNotificationPolicy'
                        MailboxIntelligenceQuarantineTag   = 'DefaultFullAccessWithNotificationPolicy'
                        SpoofQuarantineTag                 = 'DefaultFullAccessWithNotificationPolicy'
                    }
                )
            }
            Mock Get-SafeAttachmentPolicy { @() }
        }
        It 'Does not produce a Fail or Warning (regression test for the preset false-positive bug)' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
            $results | Where-Object { $_.Result -in @('Fail', 'Warning') } | Should -BeNullOrEmpty
        }
    }

    Context 'Custom anti-spam policy with full-access High-Confidence Phish tag' {
        BeforeAll {
            Mock Get-QuarantinePolicy {
                @(
                    New-METQuarantinePolicy -Name 'CustomFullAccess' -PermissionToRelease $true
                )
            }
            Mock Get-HostedContentFilterPolicy {
                @(
                    [PSCustomObject]@{
                        Name                              = 'Custom Anti-Spam Policy'
                        HighConfidencePhishQuarantineTag  = 'CustomFullAccess'
                        PhishQuarantineTag                = $null
                        HighConfidenceSpamQuarantineTag   = $null
                        SpamQuarantineTag                 = $null
                        BulkQuarantineTag                 = $null
                    }
                )
            }
            Mock Get-MalwareFilterPolicy { @() }
            Mock Get-AntiPhishPolicy { @() }
            Mock Get-SafeAttachmentPolicy { @() }
        }
        It 'Returns Fail' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Finding | Should -Match 'High-Confidence Phish'
        }
    }

    Context 'Custom anti-malware policy with no-access Malware tag' {
        BeforeAll {
            Mock Get-QuarantinePolicy {
                @(
                    New-METQuarantinePolicy -Name 'AdminOnlyAccessPolicy' -PermissionToRelease $false
                )
            }
            Mock Get-HostedContentFilterPolicy { @() }
            Mock Get-MalwareFilterPolicy {
                @(
                    [PSCustomObject]@{
                        Name         = 'Custom Anti-Malware Policy'
                        QuarantineTag = 'AdminOnlyAccessPolicy'
                    }
                )
            }
            Mock Get-AntiPhishPolicy { @() }
            Mock Get-SafeAttachmentPolicy { @() }
        }
        It 'Returns Pass' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
        }
    }

    Context 'Custom anti-phish policy with full-access Spoof/Impersonation tags' {
        BeforeAll {
            Mock Get-QuarantinePolicy {
                @(
                    New-METQuarantinePolicy -Name 'DefaultFullAccessWithNotificationPolicy' -PermissionToRelease $true
                )
            }
            Mock Get-HostedContentFilterPolicy { @() }
            Mock Get-MalwareFilterPolicy { @() }
            Mock Get-AntiPhishPolicy {
                @(
                    [PSCustomObject]@{
                        Name                              = 'Custom Anti-Phish Policy'
                        TargetedUserQuarantineTag          = 'DefaultFullAccessWithNotificationPolicy'
                        TargetedDomainQuarantineTag        = $null
                        MailboxIntelligenceQuarantineTag   = $null
                        SpoofQuarantineTag                 = 'DefaultFullAccessWithNotificationPolicy'
                    }
                )
            }
            Mock Get-SafeAttachmentPolicy { @() }
        }
        It 'Does not produce a Fail or Warning (spoof/impersonation have no restrictive floor)' {
            $results = & $checkFile
            $results | Where-Object { $_.Result -in @('Fail', 'Warning') } | Should -BeNullOrEmpty
            $results[0].Result | Should -Be 'Pass'
        }
    }

    Context 'Quarantine policy retrieval throws' {
        BeforeAll {
            Mock Get-QuarantinePolicy { throw 'Access denied' }
        }
        It 'Returns Fail with Error populated' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Error | Should -Match 'Access denied'
        }
    }

    Context 'Mixed: one custom Fail plus one preset that would have failed under the old logic' {
        BeforeAll {
            Mock Get-QuarantinePolicy {
                @(
                    New-METQuarantinePolicy -Name 'CustomFullAccess' -PermissionToRelease $true
                    New-METQuarantinePolicy -Name 'DefaultFullAccessWithNotificationPolicy' -PermissionToRelease $true
                )
            }
            Mock Get-HostedContentFilterPolicy {
                @(
                    [PSCustomObject]@{
                        Name                              = 'Custom Anti-Spam Policy'
                        HighConfidencePhishQuarantineTag  = 'CustomFullAccess'
                        PhishQuarantineTag                = $null
                        HighConfidenceSpamQuarantineTag   = $null
                        SpamQuarantineTag                 = $null
                        BulkQuarantineTag                 = $null
                    }
                )
            }
            Mock Get-MalwareFilterPolicy { @() }
            Mock Get-AntiPhishPolicy {
                @(
                    [PSCustomObject]@{
                        Name                              = 'Strict Preset Security Policy1707729536596'
                        TargetedUserQuarantineTag          = 'DefaultFullAccessWithNotificationPolicy'
                        TargetedDomainQuarantineTag        = 'DefaultFullAccessWithNotificationPolicy'
                        MailboxIntelligenceQuarantineTag   = 'DefaultFullAccessWithNotificationPolicy'
                        SpoofQuarantineTag                 = 'DefaultFullAccessWithNotificationPolicy'
                    }
                )
            }
            Mock Get-SafeAttachmentPolicy { @() }
        }
        It 'Only surfaces the custom-policy failure, preset assignments are excluded' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Finding | Should -Match 'Custom Anti-Spam Policy'
            $results[0].Finding | Should -Not -Match 'Strict Preset Security Policy'
        }
    }
}
