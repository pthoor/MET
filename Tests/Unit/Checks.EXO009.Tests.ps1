BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METPresetSecurityPolicyTier.ps1"
    . "$root/Private/Test-METIsPresetSecurityPolicyName.ps1"

    function Get-QuarantinePolicy { [CmdletBinding()] param([string]$Identity,[string]$QuarantinePolicyType) }
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

    # PermissionToRelease is reached through a nested property. A quarantine policy
    # object that omits EndUserQuarantinePermissions makes the whole expression $null,
    # so the self-release test must not silently treat that as "prevented".
    Context 'The referenced quarantine policy omits EndUserQuarantinePermissions' {
        BeforeAll {
            Mock Get-QuarantinePolicy {
                @([PSCustomObject]@{ Name = 'ContosoCustomTag' })
            }
            Mock Get-HostedContentFilterPolicy { @() }
            Mock Get-MalwareFilterPolicy {
                @([PSCustomObject]@{ Name = 'Custom Anti-Malware Policy'; QuarantineTag = 'ContosoCustomTag' })
            }
            Mock Get-AntiPhishPolicy { @() }
            Mock Get-SafeAttachmentPolicy { @() }
        }

        It 'Reports the release permission as unconfirmed instead of assuming it is prevented' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Not -Match 'prevent user self-release'
            $results[0].Finding | Should -Match 'not returned'
        }
    }

    Context 'The referenced quarantine policy has EndUserQuarantinePermissions but no PermissionToRelease member' {
        BeforeAll {
            Mock Get-QuarantinePolicy {
                @([PSCustomObject]@{ Name = 'ContosoCustomTag'; EndUserQuarantinePermissions = [PSCustomObject]@{} })
            }
            Mock Get-HostedContentFilterPolicy { @() }
            Mock Get-MalwareFilterPolicy {
                @([PSCustomObject]@{ Name = 'Custom Anti-Malware Policy'; QuarantineTag = 'ContosoCustomTag' })
            }
            Mock Get-AntiPhishPolicy { @() }
            Mock Get-SafeAttachmentPolicy { @() }
        }

        It 'Reports the release permission as unconfirmed instead of assuming it is prevented' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Not -Match 'prevent user self-release'
            $results[0].Finding | Should -Match 'not returned'
        }
    }

    Context 'A preset-generated policy references a restricted-verdict tag with EndUserQuarantinePermissions absent' {
        BeforeAll {
            Mock Get-QuarantinePolicy {
                @([PSCustomObject]@{ Name = 'ContosoCustomTag' })
            }
            Mock Get-HostedContentFilterPolicy { @() }
            Mock Get-MalwareFilterPolicy {
                @([PSCustomObject]@{ Name = 'Strict Preset Security Policy1707729536596'; QuarantineTag = 'ContosoCustomTag' })
            }
            Mock Get-AntiPhishPolicy { @() }
            Mock Get-SafeAttachmentPolicy { @() }
        }

        It 'Skips the preset assignment entirely and does not emit a Warning for the absent property' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Pass'
            $results | Where-Object { $_.Result -in @('Fail', 'Warning') } | Should -BeNullOrEmpty
        }
    }

    # A confirmed failure on one assignment must not silently drop an unconfirmed
    # permission on a different assignment - both are signals about a control this
    # check could not fully verify, and only one of them is a fixable "flip a bit".
    Context 'One assignment is a confirmed Fail, a different assignment has an unconfirmed release permission' {
        BeforeAll {
            Mock Get-QuarantinePolicy {
                @(
                    New-METQuarantinePolicy -Name 'CustomFullAccess' -PermissionToRelease $true
                    [PSCustomObject]@{ Name = 'ContosoCustomTag' }
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
            Mock Get-MalwareFilterPolicy {
                @([PSCustomObject]@{ Name = 'Custom Anti-Malware Policy'; QuarantineTag = 'ContosoCustomTag' })
            }
            Mock Get-AntiPhishPolicy { @() }
            Mock Get-SafeAttachmentPolicy { @() }
        }

        It 'Returns Fail and names both the confirmed failure and the unconfirmed tag, with Error populated' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Fail'
            $results[0].Finding | Should -Match 'Custom Anti-Spam Policy'
            $results[0].Finding | Should -Match 'High-Confidence Phish'
            $results[0].Finding | Should -Match 'Custom Anti-Malware Policy'
            $results[0].Finding | Should -Match 'not returned'
            $results[0].Finding | Should -Match 'unconfirmed release permission rather than a confirmed failure'
            $results[0].Error | Should -Not -BeNullOrEmpty
            $results[0].Error | Should -Match 'ContosoCustomTag'
        }
    }

    # Two independent unconfirmed signals in the same run - a permission that was
    # never returned, and a policy family that could not be retrieved at all - must
    # both survive into the single Warning result, not just the first one found.
    Context 'One assignment has an unconfirmed release permission and a different policy family failed to retrieve' {
        BeforeAll {
            Mock Get-QuarantinePolicy {
                @([PSCustomObject]@{ Name = 'ContosoCustomTag' })
            }
            Mock Get-HostedContentFilterPolicy { @() }
            Mock Get-MalwareFilterPolicy {
                @([PSCustomObject]@{ Name = 'Custom Anti-Malware Policy'; QuarantineTag = 'ContosoCustomTag' })
            }
            Mock Get-AntiPhishPolicy { @() }
            Mock Get-SafeAttachmentPolicy { throw 'Access denied' }
        }

        It 'Returns Warning naming both the unconfirmed permission and the retrieval failure' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'Custom Anti-Malware Policy'
            $results[0].Finding | Should -Match 'not returned'
            $results[0].Finding | Should -Match 'could not be retrieved'
            $results[0].Finding | Should -Match 'Access denied'
            $results[0].Error | Should -Not -BeNullOrEmpty
        }
    }

    # The Fail branch previously built its Finding from $fails alone, dropping a
    # co-occurring retrieval failure from a different policy family entirely - the
    # same asymmetry commit f91583d already closed for $permissionWarnings.
    Context 'One assignment is a confirmed Fail and a different policy family failed to retrieve' {
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
            Mock Get-SafeAttachmentPolicy { throw 'Access denied' }
        }

        It 'Returns Fail and names both the confirmed failure and the retrieval failure, with Error populated' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Fail'
            $results[0].Finding | Should -Match 'Custom Anti-Spam Policy'
            $results[0].Finding | Should -Match 'High-Confidence Phish'
            $results[0].Finding | Should -Match 'could not be retrieved'
            $results[0].Finding | Should -Match 'rather than a confirmed failure'
            $results[0].Finding | Should -Match 'Access denied'
            $results[0].Error | Should -Not -BeNullOrEmpty
            $results[0].Error | Should -Match 'Access denied'
        }
    }
}
