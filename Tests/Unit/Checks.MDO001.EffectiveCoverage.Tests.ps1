BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METAssessableMailboxes.ps1"
    . "$root/Private/Expand-METGroupMembership.ps1"
    . "$root/Private/Expand-METRuleRecipients.ps1"
    . "$root/Private/Resolve-METSafeLinksEffectivePolicy.ps1"
    . "$root/Private/Get-METPolicyOrderingObservations.ps1"

    function Get-EXOMailbox { [CmdletBinding()] param([string]$ResultSize,[string]$PropertySets) }
    function Get-SafeLinksRule { [CmdletBinding()] param() }
    function Get-SafeLinksPolicy { [CmdletBinding()] param() }
    function Get-ATPProtectionPolicyRule { [CmdletBinding()] param() }
    function Get-MgGroup { [CmdletBinding()] param([string]$Filter) }
    function Get-DistributionGroupMember { [CmdletBinding()] param([string]$Identity) }

    function New-TestSafeLinksPolicy {
        param([string] $Name, [bool] $Compliant)
        [PSCustomObject]@{
            Name = $Name
            EnableSafeLinksForEmail = $Compliant
            EnableSafeLinksForOffice = $Compliant
            TrackClicks = $true
            EnableForInternalSenders = $Compliant
            ScanUrls = $Compliant
            DeliverMessageAfterScan = $Compliant
            AllowClickThrough = -not $Compliant
            DisableURLRewrite = $false
        }
    }

    function New-TestSafeLinksRule {
        param([string]$Name,[string]$Policy,[int]$Priority,[string[]]$Domains)
        [PSCustomObject]@{
            Name = $Name; SafeLinksPolicy = $Policy; Priority = $Priority; State = 'Enabled'
            SentTo = $null; SentToMemberOf = $null; RecipientDomainIs = $Domains
            ExceptIfSentTo = $null; ExceptIfSentToMemberOf = $null; ExceptIfRecipientDomainIs = $null
        }
    }
}

Describe 'MET-MDO001 effective recipient coverage' {
    BeforeEach {
        $script:METContext = $null
        $script:checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'MDO' 'MET-MDO001-SafeLinks.ps1'
        Mock Get-EXOMailbox {
            [PSCustomObject]@{ PrimarySmtpAddress = 'alice@thoor.tech' }
            [PSCustomObject]@{ PrimarySmtpAddress = 'bob@thoorsec.onmicrosoft.com' }
        }
        Mock Get-ATPProtectionPolicyRule { @() }
    }

    It 'warns when a compliant priority-zero catch-all shadows a weak lower policy' {
        Mock Get-SafeLinksRule {
            @(
                New-TestSafeLinksRule -Name 'Strict custom' -Policy 'Strict custom' -Priority 0
                New-TestSafeLinksRule -Name 'Weak old policy' -Policy 'Weak old policy' -Priority 1
            )
        }
        Mock Get-SafeLinksPolicy {
            @(
                New-TestSafeLinksPolicy -Name 'Strict custom' -Compliant $true
                New-TestSafeLinksPolicy -Name 'Weak old policy' -Compliant $false
            )
        }

        $results = @(& $script:checkFile)

        $results | Should -HaveCount 1
        $results[0].Result | Should -Be 'Warning'
        $results[0].Metadata.TotalRecipients | Should -Be 2
        ($results[0].Metadata.Policies | Where-Object PolicyName -eq 'Weak old policy').EffectiveRecipientCount | Should -Be 0
        $results[0].Finding | Should -Match 'Catch-all \(no inclusion conditions\)'
        $results[0].Finding | Should -Match 'shadowed for all current recipients'
        $results[0].Finding | Should -Match 'Move the catch-all below specialized custom policies'
    }

    It 'fails only the recipient outside a compliant domain-scoped policy' {
        Mock Get-SafeLinksRule {
            @(
                New-TestSafeLinksRule -Name 'Strict domain' -Policy 'Strict domain' -Priority 0 -Domains @('thoor.tech')
                New-TestSafeLinksRule -Name 'Weak fallback' -Policy 'Weak fallback' -Priority 1
            )
        }
        Mock Get-SafeLinksPolicy {
            @(
                New-TestSafeLinksPolicy -Name 'Strict domain' -Compliant $true
                New-TestSafeLinksPolicy -Name 'Weak fallback' -Compliant $false
            )
        }

        $result = & $script:checkFile

        $result.Result | Should -Be 'Fail'
        $result.Metadata.CompliantRecipients | Should -Be 1
        $result.Metadata.AffectedRecipients | Should -Be @('bob@thoorsec.onmicrosoft.com')
        $result.Finding | Should -Match 'bob@thoorsec.onmicrosoft.com'
        $result.Finding | Should -Match 'Safe Links for email is disabled'
    }

    It 'excludes discovery mailboxes from the assessment population' {
        Mock Get-EXOMailbox {
            [PSCustomObject]@{ PrimarySmtpAddress = 'alice@thoor.tech'; RecipientTypeDetails = 'UserMailbox' }
            [PSCustomObject]@{ PrimarySmtpAddress = 'DiscoverySearchMailbox@thoorsec.onmicrosoft.com'; RecipientTypeDetails = 'DiscoveryMailbox' }
        }
        Mock Get-SafeLinksRule { @(New-TestSafeLinksRule -Name 'Strict custom' -Policy 'Strict custom' -Priority 0) }
        Mock Get-SafeLinksPolicy { @(New-TestSafeLinksPolicy -Name 'Strict custom' -Compliant $true) }

        $result = & $script:checkFile

        $result.Result | Should -Be 'Pass'
        $result.Metadata.TotalRecipients | Should -Be 1
        $result.Metadata.AffectedRecipients | Should -Not -Contain 'DiscoverySearchMailbox@thoorsec.onmicrosoft.com'
    }

    It 'returns NotApplicable when no assessable mailboxes remain' {
        Mock Get-EXOMailbox {
            [PSCustomObject]@{ PrimarySmtpAddress = 'DiscoverySearchMailbox@contoso.com'; RecipientTypeDetails = 'DiscoveryMailbox' }
        }

        $result = & $script:checkFile

        $result.Result | Should -Be 'NotApplicable'
    }

    It 'returns Warning when mailbox inventory retrieval fails' {
        Mock Get-EXOMailbox { throw 'mailbox access denied' }

        $result = & $script:checkFile

        $result.Result | Should -Be 'Warning'
        $result.Error | Should -Match 'mailbox access denied'
    }

    It 'returns Warning when a scoped group cannot be expanded' {
        $groupRule = New-TestSafeLinksRule -Name 'Group policy' -Policy 'Group policy' -Priority 0
        $groupRule.SentToMemberOf = @('security@thoor.tech')
        Mock Get-SafeLinksRule { @($groupRule) }
        Mock Get-SafeLinksPolicy {
            @(
                New-TestSafeLinksPolicy -Name 'Group policy' -Compliant $true
                New-TestSafeLinksPolicy -Name 'Built-In Protection Policy' -Compliant $true
            )
        }
        Mock Get-MgGroup { throw 'group lookup denied' }
        Mock Get-DistributionGroupMember { throw 'group lookup denied' }

        $result = & $script:checkFile

        $result.Result | Should -Be 'Warning'
        $result.Error | Should -Match 'security@thoor.tech'
    }

    It 'applies a parent-domain policy to subdomain recipients through the full check' {
        Mock Get-EXOMailbox {
            [PSCustomObject]@{ PrimarySmtpAddress = 'alice@thoor.tech'; RecipientTypeDetails = 'UserMailbox' }
            [PSCustomObject]@{ PrimarySmtpAddress = 'bob@lab.thoor.tech'; RecipientTypeDetails = 'UserMailbox' }
        }
        Mock Get-SafeLinksRule {
            @(
                New-TestSafeLinksRule -Name 'Strict domain' -Policy 'Strict domain' -Priority 0 -Domains @('thoor.tech')
                New-TestSafeLinksRule -Name 'Weak fallback' -Policy 'Weak fallback' -Priority 1
            )
        }
        Mock Get-SafeLinksPolicy {
            @(
                New-TestSafeLinksPolicy -Name 'Strict domain' -Compliant $true
                New-TestSafeLinksPolicy -Name 'Weak fallback' -Compliant $false
            )
        }

        $result = & $script:checkFile

        $result.Result | Should -Be 'Pass'
        ($result.Metadata.Policies | Where-Object PolicyName -eq 'Strict domain').EffectiveRecipientCount | Should -Be 2
    }

    It 'ignores a disabled higher-priority rule' {
        $disabled = New-TestSafeLinksRule -Name 'Disabled weak' -Policy 'Disabled weak' -Priority 0
        $disabled.State = 'Disabled'
        Mock Get-SafeLinksRule {
            @(
                $disabled
                New-TestSafeLinksRule -Name 'Enabled strict' -Policy 'Enabled strict' -Priority 1
            )
        }
        Mock Get-SafeLinksPolicy {
            @(
                New-TestSafeLinksPolicy -Name 'Disabled weak' -Compliant $false
                New-TestSafeLinksPolicy -Name 'Enabled strict' -Compliant $true
            )
        }

        $result = & $script:checkFile

        $result.Result | Should -Be 'Pass'
        ($result.Metadata.Policies | Where-Object PolicyName -eq 'Disabled weak').EffectiveRecipientCount | Should -Be 0
    }
}
