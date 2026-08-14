BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METAssessableMailboxes.ps1"
    . "$root/Private/Expand-METGroupMembership.ps1"
    . "$root/Private/Expand-METRuleRecipients.ps1"
    . "$root/Private/Resolve-METEffectivePolicy.ps1"
    . "$root/Private/New-METEffectivePolicyCoverageResult.ps1"
    . "$root/Private/Get-METPolicyOrderingObservations.ps1"

    function Get-EXOMailbox { [CmdletBinding()] param([string]$ResultSize,[string]$PropertySets) }
    function Get-MalwareFilterRule { [CmdletBinding()] param() }
    function Get-MalwareFilterPolicy { [CmdletBinding()] param() }
    function Get-HostedContentFilterRule { [CmdletBinding()] param() }
    function Get-HostedContentFilterPolicy { [CmdletBinding()] param() }
    function Get-HostedOutboundSpamFilterRule { [CmdletBinding()] param() }
    function Get-HostedOutboundSpamFilterPolicy { [CmdletBinding()] param() }
    function Get-ATPProtectionPolicyRule { [CmdletBinding()] param() }
    function Get-MgGroup { [CmdletBinding()] param([string]$Filter) }
    function Get-DistributionGroupMember { [CmdletBinding()] param([string]$Identity) }

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
