BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METAssessableMailboxes.ps1"
    . "$root/Private/Expand-METGroupMembership.ps1"
    . "$root/Private/Expand-METRuleRecipients.ps1"
    . "$root/Private/Resolve-METEffectivePolicy.ps1"
    . "$root/Private/New-METEffectivePolicyCoverageResult.ps1"
    . "$root/Private/Get-METPolicyOrderingObservations.ps1"

    function Get-EXOMailbox { [CmdletBinding()] param([string]$ResultSize,[string]$PropertySets,[string[]]$Properties,[string]$Filter) }
    function Get-MalwareFilterRule { [CmdletBinding()] param() }
    function Get-MalwareFilterPolicy { [CmdletBinding()] param() }
    function Get-HostedContentFilterRule { [CmdletBinding()] param() }
    function Get-HostedContentFilterPolicy { [CmdletBinding()] param() }
    function Get-HostedOutboundSpamFilterRule { [CmdletBinding()] param() }
    function Get-HostedOutboundSpamFilterPolicy { [CmdletBinding()] param() }
    function Get-ATPProtectionPolicyRule { [CmdletBinding()] param([string]$Identity) }
    function Get-EOPProtectionPolicyRule { [CmdletBinding()] param([string]$Identity) }
    function Get-MgGroup { [CmdletBinding()] param([string]$Filter,[int]$Top) }
    function Get-MgGroupTransitiveMember { [CmdletBinding()] param([string]$GroupId,[switch]$All) }
    function Get-DistributionGroupMember { [CmdletBinding()] param([string]$Identity,[string]$ResultSize) }
    function Get-UnifiedGroupLinks { [CmdletBinding()] param([string]$Identity,[string]$LinkType,[string]$ResultSize) }

    function New-Rule {
        param([string]$Name,[string]$Link,[int]$Priority=0,[string[]]$Domains,[switch]$Outbound)
        $rule = [PSCustomObject]@{ Name=$Name; Priority=$Priority; State='Enabled' }
        if ($Outbound) {
            $rule | Add-Member HostedOutboundSpamFilterPolicy $Link
            $rule | Add-Member From $null; $rule | Add-Member FromMemberOf $null; $rule | Add-Member SenderDomainIs $Domains
            $rule | Add-Member ExceptIfFrom $null; $rule | Add-Member ExceptIfFromMemberOf $null; $rule | Add-Member ExceptIfSenderDomainIs $null
        } else {
            $rule | Add-Member SentTo $null; $rule | Add-Member SentToMemberOf $null; $rule | Add-Member RecipientDomainIs $Domains
            $rule | Add-Member ExceptIfSentTo $null; $rule | Add-Member ExceptIfSentToMemberOf $null; $rule | Add-Member ExceptIfRecipientDomainIs $null
        }
        $rule
    }
}

Describe 'MET-MDO005 anti-malware effective coverage' {
    BeforeEach {
        $script:METContext=$null
        Mock Get-EXOMailbox { [PSCustomObject]@{PrimarySmtpAddress='a@contoso.com';RecipientTypeDetails='UserMailbox'}; [PSCustomObject]@{PrimarySmtpAddress='b@other.com';RecipientTypeDetails='UserMailbox'} }
        Mock Get-ATPProtectionPolicyRule { @() }
        Mock Get-EOPProtectionPolicyRule { @() }
    }
    It 'does not require legacy admin notifications and ignores a shadowed weak policy' {
        $strong=New-Rule strong strong 0
        $weak=New-Rule weak weak 1
        $strong | Add-Member MalwareFilterPolicy strong; $weak | Add-Member MalwareFilterPolicy weak
        Mock Get-MalwareFilterRule { @($strong,$weak) }
        Mock Get-MalwareFilterPolicy {
            [PSCustomObject]@{Name='strong';ZapEnabled=$true;EnableFileFilter=$true;FileTypeAction='Reject';QuarantineTag='AdminOnlyAccessPolicy';EnableInternalSenderAdminNotifications=$false;EnableExternalSenderAdminNotifications=$false}
            [PSCustomObject]@{Name='weak';ZapEnabled=$false;EnableFileFilter=$false;FileTypeAction='Allow';QuarantineTag='Other'}
        }
        $result=& "$root/Checks/MDO/MET-MDO005-AntiMalware.ps1"
        $result.Result | Should -Be Warning
        ($result.Metadata.Policies | Where-Object PolicyName -eq weak).EffectiveRecipientCount | Should -Be 0
        $result.Metadata.OrderingObservations.Message | Should -Match 'higher-precedence custom catch-all policy'
        # Regression: zero affected recipients + a Warning-severity ordering observation must not
        # produce a headline that falsely claims full compliance (New-METEffectivePolicyCoverageResult).
        $result.Finding | Should -Match 'ordering issue worth reviewing'
        $result.Finding | Should -Not -Match 'meets the baseline\.\r?\nPolicy coverage'
    }
    It 'warns rather than passes when policy retrieval fails' {
        Mock Get-MalwareFilterRule { @() }; Mock Get-MalwareFilterPolicy { throw 'denied' }
        $result=& "$root/Checks/MDO/MET-MDO005-AntiMalware.ps1"
        $result.Result | Should -Be Warning
    }
}

Describe 'MET-MDO006 inbound anti-spam effective coverage' {
    BeforeEach {
        $script:METContext=$null
        Mock Get-EXOMailbox { [PSCustomObject]@{PrimarySmtpAddress='a@sub.contoso.com';RecipientTypeDetails='UserMailbox'}; [PSCustomObject]@{PrimarySmtpAddress='b@other.com';RecipientTypeDetails='UserMailbox'} }
        Mock Get-ATPProtectionPolicyRule { @() }
        Mock Get-EOPProtectionPolicyRule { @() }
    }
    It 'applies domain and catch-all policies by priority and reports only affected recipients' {
        $domain=New-Rule domain domain 0 @('contoso.com'); $domain | Add-Member HostedContentFilterPolicy domain
        $fallback=New-Rule fallback fallback 1; $fallback | Add-Member HostedContentFilterPolicy fallback
        Mock Get-HostedContentFilterRule { @($domain,$fallback) }
        Mock Get-HostedContentFilterPolicy {
            [PSCustomObject]@{Name='domain';SpamAction='MoveToJmf';HighConfidenceSpamAction='Quarantine';PhishSpamAction='Quarantine';HighConfidencePhishAction='Quarantine';BulkThreshold=6;HighConfidencePhishQuarantineTag='AdminOnlyAccessPolicy';AllowedSenders=@();AllowedSenderDomains=@()}
            [PSCustomObject]@{Name='fallback';SpamAction='MoveToJmf';HighConfidenceSpamAction='MoveToJmf';PhishSpamAction='MoveToJmf';HighConfidencePhishAction='Quarantine';BulkThreshold=7;HighConfidencePhishQuarantineTag='DefaultFullAccessWithNotificationPolicy';AllowedSenders=@();AllowedSenderDomains=@()}
        }
        $result=& "$root/Checks/MDO/MET-MDO006-AntiSpamInbound.ps1"
        $result.Result | Should -Be Fail
        $result.Metadata.AffectedRecipients | Should -Be @('b@other.com')
        $result.Finding | Should -Match 'users still cannot self-release'
    }
}

Describe 'MET-MDO007 outbound anti-spam effective coverage' {
    BeforeEach {
        $script:METContext=$null
        Mock Get-EXOMailbox { [PSCustomObject]@{PrimarySmtpAddress='a@sub.contoso.com';RecipientTypeDetails='UserMailbox'}; [PSCustomObject]@{PrimarySmtpAddress='b@other.com';RecipientTypeDetails='UserMailbox'} }
    }
    It 'uses sender-domain scope including subdomains' {
        $domain=New-Rule domain domain 0 @('contoso.com') -Outbound
        Mock Get-HostedOutboundSpamFilterRule { @($domain) }
        Mock Get-HostedOutboundSpamFilterPolicy {
            [PSCustomObject]@{Name='domain';AutoForwardingMode='Off';ActionWhenThresholdReached='BlockUser'}
            [PSCustomObject]@{Name='Default';IsDefault=$true;AutoForwardingMode='On';ActionWhenThresholdReached='BlockUser'}
        }
        $result=& "$root/Checks/MDO/MET-MDO007-AntiSpamOutbound.ps1"
        $result.Result | Should -Be Fail
        $result.Severity | Should -Be 'High'
        $result.Metadata.AffectedRecipients | Should -Be @('b@other.com')
    }
    It 'reports Automatic as Warning and does not require legacy notification recipients' {
        Mock Get-HostedOutboundSpamFilterRule { @() }
        Mock Get-HostedOutboundSpamFilterPolicy { [PSCustomObject]@{Name='Default';IsDefault=$true;AutoForwardingMode='Automatic';ActionWhenThresholdReached='BlockUser';NotifyOutboundSpamRecipients=@()} }
        $result=& "$root/Checks/MDO/MET-MDO007-AntiSpamOutbound.ps1"
        $result.Result | Should -Be Warning
        $result.Finding | Should -Not -Match 'notification address'
        $result.Finding | Should -Match 'system-controlled'
    }
}


Describe 'MET-MDO005 common attachment filter file types' {
    BeforeEach {
        $script:METContext=$null
        Mock Get-EXOMailbox { [PSCustomObject]@{PrimarySmtpAddress='a@contoso.com';RecipientTypeDetails='UserMailbox'} }
        Mock Get-ATPProtectionPolicyRule { @() }
        Mock Get-EOPProtectionPolicyRule { @() }
        Mock Get-MalwareFilterRule { @() }
    }

    Context 'The file type list covers every high-risk extension' {
        It 'Returns Pass and reports no missing file types' {
            Mock Get-MalwareFilterPolicy {
                [PSCustomObject]@{Name='Default';IsDefault=$true;ZapEnabled=$true;EnableFileFilter=$true;FileTypeAction='Reject';QuarantineTag='AdminOnlyAccessPolicy';FileTypes=@('exe','com','scr','pif','cmd','bat','vbs','vbe','js','jse','wsf','wsh','hta','ps1','msi','lnk','jar','reg','cpl','dll','docm')}
            }
            $result=& "$root/Checks/MDO/MET-MDO005-AntiMalware.ps1"
            $result.CheckId | Should -Be 'MET-MDO005'
            $result.Severity | Should -Be 'High'
            $result.Result | Should -Be 'Pass'
            $result.Finding | Should -Not -Match 'high-risk file types'
        }
    }

    Context 'The file type list omits high-risk extensions' {
        It 'Names the missing extensions once, sorted, and normalises case and leading dots' {
            Mock Get-MalwareFilterPolicy {
                [PSCustomObject]@{Name='Default';IsDefault=$true;ZapEnabled=$true;EnableFileFilter=$true;FileTypeAction='Reject';QuarantineTag='AdminOnlyAccessPolicy';FileTypes=@('.EXE ','com','SCR','pif','cmd','bat','vbs','vbe','js','jse','wsf','wsh','ps1','msi','jar','reg','cpl','dll')}
            }
            $result=& "$root/Checks/MDO/MET-MDO005-AntiMalware.ps1"
            $result.Result | Should -Be 'Fail'
            $result.Finding | Should -Match 'does not block high-risk file types: hta, lnk'
            $result.Finding | Should -Not -Match 'high-risk file types.*exe'
        }
    }

    Context 'The filter is enabled with an empty file type list' {
        It 'Reports that the filter blocks nothing' {
            Mock Get-MalwareFilterPolicy {
                [PSCustomObject]@{Name='Default';IsDefault=$true;ZapEnabled=$true;EnableFileFilter=$true;FileTypeAction='Reject';QuarantineTag='AdminOnlyAccessPolicy';FileTypes=@()}
            }
            $result=& "$root/Checks/MDO/MET-MDO005-AntiMalware.ps1"
            $result.Result | Should -Be 'Fail'
            $result.Finding | Should -Match 'file type list is empty'
            $result.Finding | Should -Not -Match 'does not block high-risk file types'
        }
    }

    Context 'The filter is disabled' {
        It 'Does not duplicate the disabled-filter finding with a file type finding' {
            Mock Get-MalwareFilterPolicy {
                [PSCustomObject]@{Name='Default';IsDefault=$true;ZapEnabled=$true;EnableFileFilter=$false;FileTypeAction='Reject';QuarantineTag='AdminOnlyAccessPolicy';FileTypes=@()}
            }
            $result=& "$root/Checks/MDO/MET-MDO005-AntiMalware.ps1"
            $result.Finding | Should -Match 'Common attachment filter is disabled'
            $result.Finding | Should -Not -Match 'file type list is empty'
            $result.Finding | Should -Not -Match 'does not block high-risk file types'
        }
    }

    Context 'The policy object does not expose FileTypes' {
        It 'Does not assess the file type list' {
            Mock Get-MalwareFilterPolicy {
                [PSCustomObject]@{Name='Default';IsDefault=$true;ZapEnabled=$true;EnableFileFilter=$true;FileTypeAction='Reject';QuarantineTag='AdminOnlyAccessPolicy'}
            }
            $result=& "$root/Checks/MDO/MET-MDO005-AntiMalware.ps1"
            $result.Result | Should -Be 'Pass'
            $result.Finding | Should -Not -Match 'file type list is empty'
            $result.Finding | Should -Not -Match 'does not block high-risk file types'
        }
    }
}

Describe 'MET-MDO005/006/007 absent-property handling' {
    BeforeEach {
        $script:METContext = $null
        Mock Get-EXOMailbox { [PSCustomObject]@{PrimarySmtpAddress='a@contoso.com';RecipientTypeDetails='UserMailbox'} }
        Mock Get-ATPProtectionPolicyRule { @() }
        Mock Get-EOPProtectionPolicyRule { @() }
    }

    # ZapEnabled and EnableFileFilter are read with -not, which collapses an absent
    # property into $false.
    Context 'MET-MDO005: the effective anti-malware policy omits ZapEnabled and EnableFileFilter' {
        BeforeEach {
            Mock Get-MalwareFilterRule { @() }
            Mock Get-MalwareFilterPolicy {
                [PSCustomObject]@{ Name='Default'; IsDefault=$true; FileTypeAction='Reject'; QuarantineTag='AdminOnlyAccessPolicy' }
            }
        }

        It 'Does not return Pass on settings it never observed' {
            $result = & "$root/Checks/MDO/MET-MDO005-AntiMalware.ps1"
            $result.Result | Should -Not -Be 'Pass'
        }

        # Pins current behaviour, whose wording is wrong: the check reports malware ZAP and
        # the common attachment filter as disabled on the strength of properties Exchange
        # Online never returned. The verdict is fail-closed and safe, but the sentence
        # states an observation that was not made. Left pinned rather than corrected here
        # so the defect is visible and cannot change unnoticed.
        It 'Currently states both settings are disabled rather than that they were not returned' {
            $result = & "$root/Checks/MDO/MET-MDO005-AntiMalware.ps1"
            $result.Result | Should -Be 'Fail'
            $result.Finding | Should -Match 'ZAP for malware is disabled'
            $result.Finding | Should -Match 'Common attachment filter is disabled'
            $result.Finding | Should -Not -Match 'not returned'
        }
    }

    # BulkThreshold is the one inbound anti-spam setting tested with a numeric comparison
    # rather than an equality check. $null -gt 6 is $false, so an absent threshold raises
    # no issue at all and the policy is graded compliant on a value never read.
    Context 'MET-MDO006: an otherwise compliant anti-spam policy omits BulkThreshold' {
        BeforeEach {
            Mock Get-HostedContentFilterRule { @() }
            Mock Get-HostedContentFilterPolicy {
                [PSCustomObject]@{ Name='Default'; IsDefault=$true; SpamAction='MoveToJmf'; HighConfidenceSpamAction='Quarantine'
                    PhishSpamAction='Quarantine'; HighConfidencePhishAction='Quarantine'
                    HighConfidencePhishQuarantineTag='AdminOnlyAccessPolicy'; AllowedSenders=@(); AllowedSenderDomains=@() }
            }
        }

        It 'Does not report the recipient as fully protected on a threshold that was never observed' {
            $result = & "$root/Checks/MDO/MET-MDO006-AntiSpamInbound.ps1"
            $result.Result | Should -Not -Be 'Pass'
            $result.Finding | Should -Not -Match 'Bulk complaint level threshold'
            $result.Finding | Should -Match 'BulkThreshold was not returned'
        }
    }

    # The outbound check is the one that gets this right: AutoForwardingMode is compared
    # against the documented value set rather than tested for truth, so an absent value
    # falls outside it and is surfaced instead of being read as Off.
    Context 'MET-MDO007: the effective outbound policy omits AutoForwardingMode' {
        BeforeEach {
            Mock Get-HostedOutboundSpamFilterRule { @() }
            Mock Get-HostedOutboundSpamFilterPolicy {
                [PSCustomObject]@{ Name='Default'; IsDefault=$true; ActionWhenThresholdReached='BlockUser' }
            }
        }

        It 'Returns Warning rather than reading the absent value as disabled forwarding' {
            $result = & "$root/Checks/MDO/MET-MDO007-AntiSpamOutbound.ps1"
            $result.Result | Should -Be 'Warning'
            $result.Severity | Should -Be 'High'
            $result.Finding | Should -Match 'system-controlled rather than explicitly disabled'
            $result.Finding | Should -Not -Match 'Automatic external forwarding is enabled'
        }
    }
}


Describe 'MET-MDO005/007 inverted-sense regression guards' {
    BeforeEach {
        $script:METContext = $null
        Mock Get-EXOMailbox { [PSCustomObject]@{PrimarySmtpAddress='a@contoso.com';RecipientTypeDetails='UserMailbox'} }
        Mock Get-ATPProtectionPolicyRule { @() }
        Mock Get-EOPProtectionPolicyRule { @() }
    }

    # ZapEnabled and EnableFileFilter are both read with -not, so the secure value is
    # $true and the issue text is the negative. Reading either as "the feature is off"
    # inverts the verdict, so both senses are pinned for both properties.
    Context 'MET-MDO005 ZapEnabled and EnableFileFilter' {
        It 'Raises each issue only when its property is false' {
            Mock Get-MalwareFilterRule { @() }
            Mock Get-MalwareFilterPolicy {
                [PSCustomObject]@{ Name='Default'; IsDefault=$true; ZapEnabled=$true; EnableFileFilter=$true; FileTypeAction='Reject'; QuarantineTag='AdminOnlyAccessPolicy' }
            }
            $secure = & "$root/Checks/MDO/MET-MDO005-AntiMalware.ps1"
            $secure.Result | Should -Be 'Pass'
            $secure.Finding | Should -Not -Match 'ZAP for malware is disabled'
            $secure.Finding | Should -Not -Match 'Common attachment filter is disabled'

            Mock Get-MalwareFilterPolicy {
                [PSCustomObject]@{ Name='Default'; IsDefault=$true; ZapEnabled=$false; EnableFileFilter=$false; FileTypeAction='Reject'; QuarantineTag='AdminOnlyAccessPolicy' }
            }
            $insecure = & "$root/Checks/MDO/MET-MDO005-AntiMalware.ps1"
            $insecure.Result | Should -Be 'Fail'
            $insecure.Finding | Should -Match 'ZAP for malware is disabled'
            $insecure.Finding | Should -Match 'Common attachment filter is disabled'
        }

        It 'Keeps the two properties independent so one cannot stand in for the other' {
            Mock Get-MalwareFilterRule { @() }
            Mock Get-MalwareFilterPolicy {
                [PSCustomObject]@{ Name='Default'; IsDefault=$true; ZapEnabled=$false; EnableFileFilter=$true; FileTypeAction='Reject'; QuarantineTag='AdminOnlyAccessPolicy' }
            }
            $zapOnly = & "$root/Checks/MDO/MET-MDO005-AntiMalware.ps1"
            $zapOnly.Finding | Should -Match 'ZAP for malware is disabled'
            $zapOnly.Finding | Should -Not -Match 'Common attachment filter is disabled'

            Mock Get-MalwareFilterPolicy {
                [PSCustomObject]@{ Name='Default'; IsDefault=$true; ZapEnabled=$true; EnableFileFilter=$false; FileTypeAction='Reject'; QuarantineTag='AdminOnlyAccessPolicy' }
            }
            $filterOnly = & "$root/Checks/MDO/MET-MDO005-AntiMalware.ps1"
            $filterOnly.Finding | Should -Match 'Common attachment filter is disabled'
            $filterOnly.Finding | Should -Not -Match 'ZAP for malware is disabled'
        }
    }

    # AutoForwardingMode is the inverted one in the outbound check: 'On' is the insecure
    # value while every other setting it grades is secure when switched on.
    Context 'MET-MDO007 AutoForwardingMode' {
        It 'Flags automatic forwarding only when AutoForwardingMode is On' {
            Mock Get-HostedOutboundSpamFilterRule { @() }
            Mock Get-HostedOutboundSpamFilterPolicy {
                [PSCustomObject]@{ Name='Default'; IsDefault=$true; AutoForwardingMode='Off'; ActionWhenThresholdReached='BlockUser' }
            }
            $secure = & "$root/Checks/MDO/MET-MDO007-AntiSpamOutbound.ps1"
            $secure.Result | Should -Be 'Pass'
            $secure.Finding | Should -Not -Match 'Automatic external forwarding is enabled'

            Mock Get-HostedOutboundSpamFilterPolicy {
                [PSCustomObject]@{ Name='Default'; IsDefault=$true; AutoForwardingMode='On'; ActionWhenThresholdReached='BlockUser' }
            }
            $insecure = & "$root/Checks/MDO/MET-MDO007-AntiSpamOutbound.ps1"
            $insecure.Result | Should -Be 'Fail'
            $insecure.Finding | Should -Match 'Automatic external forwarding is enabled'
        }
    }
}
