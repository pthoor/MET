BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METAssessableMailboxes.ps1"
    . "$root/Private/Expand-METGroupMembership.ps1"
    . "$root/Private/Expand-METRuleRecipients.ps1"
    . "$root/Private/Resolve-METAntiPhishEffectivePolicy.ps1"
    . "$root/Private/Get-METPolicyOrderingObservations.ps1"
    . "$root/Private/New-METEffectivePolicyCoverageResult.ps1"

    function Get-EXOMailbox { [CmdletBinding()] param([string]$ResultSize,[string]$PropertySets) }
    function Get-AntiPhishRule { [CmdletBinding()] param() }
    function Get-AntiPhishPolicy { [CmdletBinding()] param() }
    function Get-ATPProtectionPolicyRule { [CmdletBinding()] param() }

    function New-TestAntiPhishPolicy {
        param([string]$Name,[bool]$Compliant,[bool]$Default = $false)
        [PSCustomObject]@{
            Name = $Name; IsDefault = $Default
            EnableMailboxIntelligence = $true
            EnableMailboxIntelligenceProtection = $Compliant
            MailboxIntelligenceProtectionAction = if ($Compliant) { 'Quarantine' } else { 'NoAction' }
            EnableFirstContactSafetyTips = $Compliant
            EnableSimilarUsersSafetyTips = $Compliant
            EnableSimilarDomainsSafetyTips = $Compliant
            EnableUnusualCharactersSafetyTips = $Compliant
            EnableTargetedUserProtection = $Compliant
            TargetedUsersToProtect = if ($Compliant) { @('CEO;ceo@contoso.com') } else { @() }
            TargetedUserProtectionAction = if ($Compliant) { 'Quarantine' } else { 'NoAction' }
            EnableOrganizationDomainsProtection = $Compliant
            TargetedDomainProtectionAction = if ($Compliant) { 'Quarantine' } else { 'NoAction' }
            PhishThresholdLevel = if ($Compliant) { 3 } else { 1 }
        }
    }

    function New-TestAntiPhishRule {
        param([string]$Name,[string]$Policy,[int]$Priority,[string[]]$Domains)
        [PSCustomObject]@{
            Name = $Name; AntiPhishPolicy = $Policy; Priority = $Priority; State = 'Enabled'
            SentTo = $null; SentToMemberOf = $null; RecipientDomainIs = $Domains
            ExceptIfSentTo = $null; ExceptIfSentToMemberOf = $null; ExceptIfRecipientDomainIs = $null
        }
    }
}

Describe 'MET-MDO003 effective recipient coverage' {
    BeforeEach {
        $script:METContext = $null
        $script:checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'MDO' 'MET-MDO003-AntiPhish.ps1'
        Mock Get-EXOMailbox {
            [PSCustomObject]@{ PrimarySmtpAddress = 'alice@contoso.com'; RecipientTypeDetails = 'UserMailbox' }
            [PSCustomObject]@{ PrimarySmtpAddress = 'bob@tenant.onmicrosoft.com'; RecipientTypeDetails = 'UserMailbox' }
        }
        Mock Get-ATPProtectionPolicyRule { @() }
    }

    It 'passes when a compliant catch-all custom policy shadows the weak default' {
        Mock Get-AntiPhishRule { @(New-TestAntiPhishRule -Name 'Strict custom' -Policy 'Strict custom' -Priority 0) }
        Mock Get-AntiPhishPolicy {
            @(
                New-TestAntiPhishPolicy -Name 'Strict custom' -Compliant $true
                New-TestAntiPhishPolicy -Name 'Office365 AntiPhish Default' -Compliant $false -Default $true
            )
        }

        $result = & $script:checkFile

        $result.Result | Should -Be 'Pass'
        $result.Metadata.TotalRecipients | Should -Be 2
        ($result.Metadata.Policies | Where-Object PolicyName -eq 'Strict custom').EffectiveRecipientCount | Should -Be 2
        ($result.Metadata.Policies | Where-Object PolicyType -eq 'Default').EffectiveRecipientCount | Should -Be 0
    }

    It 'fails only recipients outside a compliant domain-scoped policy' {
        Mock Get-AntiPhishRule {
            @(New-TestAntiPhishRule -Name 'Domain policy' -Policy 'Domain policy' -Priority 0 -Domains @('contoso.com'))
        }
        Mock Get-AntiPhishPolicy {
            @(
                New-TestAntiPhishPolicy -Name 'Domain policy' -Compliant $true
                New-TestAntiPhishPolicy -Name 'Office365 AntiPhish Default' -Compliant $false -Default $true
            )
        }

        $result = & $script:checkFile

        $result.Result | Should -Be 'Fail'
        $result.Metadata.AffectedRecipients | Should -Be @('bob@tenant.onmicrosoft.com')
        $result.Finding | Should -Match 'bob@tenant.onmicrosoft.com'
    }

    It 'does not report the targeted-user NoAction property as a separate issue when detection is disabled' {
        Mock Get-AntiPhishRule { @() }
        Mock Get-AntiPhishPolicy {
            @(New-TestAntiPhishPolicy -Name 'Office365 AntiPhish Default' -Compliant $false -Default $true)
        }

        $result = & $script:checkFile

        $result.Result | Should -Be 'Fail'
        $result.Finding | Should -Match 'has no protected users'
        $result.Finding | Should -Not -Match 'Targeted user impersonation detections receive NoAction'
    }

    It 'returns Warning rather than Pass when policy retrieval fails' {
        Mock Get-AntiPhishRule { @() }
        Mock Get-AntiPhishPolicy { throw 'policy access denied' }

        $result = & $script:checkFile

        $result.Result | Should -Be 'Warning'
        $result.Error | Should -Match 'policy access denied'
    }
}


Describe 'MET-MDO003 custom domain impersonation protection' {
    BeforeEach {
        $script:METContext = $null
        $script:checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'MDO' 'MET-MDO003-AntiPhish.ps1'
        Mock Get-EXOMailbox {
            [PSCustomObject]@{ PrimarySmtpAddress = 'alice@contoso.com'; RecipientTypeDetails = 'UserMailbox' }
        }
        Mock Get-ATPProtectionPolicyRule { @() }
        Mock Get-AntiPhishRule { @() }
    }

    Context 'Targeted domain protection is disabled' {
        It 'Reports the missing external-domain coverage as a gap' {
            Mock Get-AntiPhishPolicy {
                $p = New-TestAntiPhishPolicy -Name 'Office365 AntiPhish Default' -Compliant $true -Default $true
                $p | Add-Member -NotePropertyName EnableTargetedDomainsProtection -NotePropertyValue $false
                $p | Add-Member -NotePropertyName TargetedDomainsToProtect -NotePropertyValue @('supplier.example')
                $p
            }

            $result = & $script:checkFile

            $result.CheckId | Should -Be 'MET-MDO003'
            $result.Severity | Should -Be 'High'
            $result.Result | Should -Be 'Fail'
            $result.Finding | Should -Match 'covers no external domains'
        }
    }

    Context 'Targeted domain protection is enabled with an empty domain list' {
        It 'Reports the gap when the list is empty' {
            Mock Get-AntiPhishPolicy {
                $p = New-TestAntiPhishPolicy -Name 'Office365 AntiPhish Default' -Compliant $true -Default $true
                $p | Add-Member -NotePropertyName EnableTargetedDomainsProtection -NotePropertyValue $true
                $p | Add-Member -NotePropertyName TargetedDomainsToProtect -NotePropertyValue @()
                $p
            }

            $result = & $script:checkFile

            $result.Result | Should -Be 'Fail'
            $result.Finding | Should -Match 'covers no external domains'
        }

        It 'Does not throw when the domain list is null' {
            Mock Get-AntiPhishPolicy {
                $p = New-TestAntiPhishPolicy -Name 'Office365 AntiPhish Default' -Compliant $true -Default $true
                $p | Add-Member -NotePropertyName EnableTargetedDomainsProtection -NotePropertyValue $true
                $p | Add-Member -NotePropertyName TargetedDomainsToProtect -NotePropertyValue $null
                $p
            }

            $result = & $script:checkFile

            $result.Result | Should -Be 'Fail'
            $result.Error | Should -BeNullOrEmpty
            $result.Finding | Should -Match 'covers no external domains'
        }
    }

    Context 'Targeted domain protection names external domains' {
        It 'Does not report a gap' {
            Mock Get-AntiPhishPolicy {
                $p = New-TestAntiPhishPolicy -Name 'Office365 AntiPhish Default' -Compliant $true -Default $true
                $p | Add-Member -NotePropertyName EnableTargetedDomainsProtection -NotePropertyValue $true
                $p | Add-Member -NotePropertyName TargetedDomainsToProtect -NotePropertyValue @('supplier.example','partner.example')
                $p
            }

            $result = & $script:checkFile

            $result.Result | Should -Be 'Pass'
            $result.Finding | Should -Not -Match 'covers no external domains'
        }
    }

    Context 'The policy object does not expose the targeted domain properties' {
        It 'Does not assess custom domain impersonation protection' {
            Mock Get-AntiPhishPolicy {
                New-TestAntiPhishPolicy -Name 'Office365 AntiPhish Default' -Compliant $true -Default $true
            }

            $result = & $script:checkFile

            $result.Result | Should -Be 'Pass'
            $result.Finding | Should -Not -Match 'covers no external domains'
        }
    }
}
