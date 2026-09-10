BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"
    . "$root/Private/Get-METRuleScope.ps1"
    . "$root/Private/Get-METAssessableMailboxes.ps1"
    . "$root/Private/Expand-METGroupMembership.ps1"
    . "$root/Private/Expand-METRuleRecipients.ps1"
    . "$root/Private/Resolve-METSafeLinksEffectivePolicy.ps1"
    . "$root/Private/Resolve-METEffectivePolicy.ps1"
    . "$root/Private/New-METEffectivePolicyCoverageResult.ps1"
    . "$root/Private/Get-METPolicyOrderingObservations.ps1"

    # Stub EXO cmdlets so Pester's Mock can override them
    function Get-SafeLinksPolicy               { [CmdletBinding()] param() }
    function Get-SafeLinksRule                 { [CmdletBinding()] param() }
    function Get-ATPProtectionPolicyRule       { [CmdletBinding()] param([string]$Identity) }
    function Get-EOPProtectionPolicyRule       { [CmdletBinding()] param([string]$Identity) }
    function Get-EXOMailbox                    { [CmdletBinding()] param([string]$ResultSize,[string]$PropertySets,[string[]]$Properties,[string]$Filter) }
    function Get-SafeAttachmentPolicy          { [CmdletBinding()] param() }
    function Get-SafeAttachmentRule            { [CmdletBinding()] param() }
    function Get-AtpPolicyForO365              { [CmdletBinding()] param() }
    function Get-AntiPhishPolicy               { [CmdletBinding()] param() }
    function Get-MalwareFilterPolicy           { [CmdletBinding()] param() }
    function Get-HostedContentFilterPolicy     { [CmdletBinding()] param() }
    function Get-HostedContentFilterRule       { [CmdletBinding()] param() }
    function Get-HostedOutboundSpamFilterPolicy { [CmdletBinding()] param() }
}

Describe 'MET-MDO002 Safe Attachments' {

    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'MDO' 'MET-MDO002-SafeAttachments.ps1'
    }

    Context 'Policy enabled with Block action' {
        BeforeAll {
            Mock Get-AtpPolicyForO365     { [PSCustomObject]@{ EnableATPForSPOTeamsODB = $true } }
            Mock Get-SafeAttachmentRule   { @() }
            Mock Get-SafeAttachmentPolicy {
                [PSCustomObject]@{ Name = 'Built-In Protection Policy'; Enable = $true; Action = 'Block' }
            }
        }
        It 'Returns Pass' {
            $results = & $checkFile
            $policyResult = $results | Where-Object { $_.AffectedObject -match 'Built-In Protection Policy' }
            $policyResult.Result | Should -Be 'Pass'
        }
    }

    Context 'Policy enabled with Allow action' {
        BeforeAll {
            Mock Get-AtpPolicyForO365     { [PSCustomObject]@{ EnableATPForSPOTeamsODB = $true } }
            Mock Get-SafeAttachmentRule   { @() }
            Mock Get-SafeAttachmentPolicy {
                [PSCustomObject]@{ Name = 'Built-In Protection Policy'; Enable = $true; Action = 'Allow' }
            }
        }
        It 'Returns Fail' {
            $results = & $checkFile
            $policyResult = $results | Where-Object { $_.AffectedObject -match 'Built-In Protection Policy' }
            $policyResult.Result | Should -Be 'Fail'
        }
        It 'Finding mentions Allow' {
            $results = & $checkFile
            $policyResult = $results | Where-Object { $_.AffectedObject -match 'Built-In Protection Policy' }
            $policyResult.Finding | Should -Match 'Allow'
        }
    }

    Context 'Policy is disabled' {
        BeforeAll {
            Mock Get-AtpPolicyForO365     { [PSCustomObject]@{ EnableATPForSPOTeamsODB = $true } }
            Mock Get-SafeAttachmentRule   { @() }
            Mock Get-SafeAttachmentPolicy {
                [PSCustomObject]@{ Name = 'Built-In Protection Policy'; Enable = $false; Action = 'Block' }
            }
        }
        It 'Returns Fail' {
            $results = & $checkFile
            $policyResult = $results | Where-Object { $_.AffectedObject -match 'Built-In Protection Policy' }
            $policyResult.Result | Should -Be 'Fail'
        }
    }

    Context 'Global SharePoint, OneDrive and Teams setting is enabled' {
        BeforeAll {
            Mock Get-AtpPolicyForO365     { [PSCustomObject]@{ EnableATPForSPOTeamsODB = $true } }
            Mock Get-SafeAttachmentRule   { @() }
            Mock Get-SafeAttachmentPolicy {
                [PSCustomObject]@{ Name = 'Built-In Protection Policy'; Enable = $true; Action = 'Block' }
            }
        }
        It 'Reports the global setting as Pass instead of emitting nothing for it' {
            $results = & $checkFile
            $globalResult = $results | Where-Object { $_.AffectedObject -eq 'Global Safe Attachments Settings' }
            $globalResult | Should -Not -BeNullOrEmpty
            $globalResult.Result | Should -Be 'Pass'
            $globalResult.Error  | Should -BeNullOrEmpty
        }
    }

    Context 'Global SharePoint, OneDrive and Teams setting is disabled' {
        BeforeAll {
            Mock Get-AtpPolicyForO365     { [PSCustomObject]@{ EnableATPForSPOTeamsODB = $false } }
            Mock Get-SafeAttachmentRule   { @() }
            Mock Get-SafeAttachmentPolicy {
                [PSCustomObject]@{ Name = 'Built-In Protection Policy'; Enable = $true; Action = 'Block' }
            }
        }
        It 'Returns Fail for the global setting' {
            $results = & $checkFile
            $globalResult = $results | Where-Object { $_.AffectedObject -eq 'Global Safe Attachments Settings' }
            $globalResult.Result | Should -Be 'Fail'
        }
    }

    Context 'Global Safe Attachments policy cannot be retrieved' {
        BeforeAll {
            Mock Get-AtpPolicyForO365     { throw 'Access denied' }
            Mock Get-SafeAttachmentRule   { @() }
            Mock Get-SafeAttachmentPolicy {
                [PSCustomObject]@{ Name = 'Built-In Protection Policy'; Enable = $true; Action = 'Block' }
            }
        }
        It 'Emits a result for the global setting carrying the failure in Error' {
            $results = & $checkFile
            $globalResult = $results | Where-Object { $_.AffectedObject -eq 'Global Safe Attachments Settings' }
            $globalResult | Should -Not -BeNullOrEmpty
            $globalResult.Error | Should -Match 'Access denied'
        }
        It 'Does not report the unread global setting as Pass' {
            $results = & $checkFile
            $globalResult = $results | Where-Object { $_.AffectedObject -eq 'Global Safe Attachments Settings' }
            $globalResult | Should -Not -BeNullOrEmpty
            $globalResult.Result | Should -Not -Be 'Pass'
        }
        It 'Finding says the setting was not established rather than naming a state' {
            $results = & $checkFile
            $globalResult = $results | Where-Object { $_.AffectedObject -eq 'Global Safe Attachments Settings' }
            $globalResult.Finding | Should -Match 'not established'
        }
        It 'Still assesses the Safe Attachment policies' {
            $results = & $checkFile
            $policyResult = $results | Where-Object { $_.AffectedObject -match 'Built-In Protection Policy' }
            $policyResult.Result | Should -Be 'Pass'
        }
    }

    Context 'Global policy does not return the EnableATPForSPOTeamsODB property' {
        BeforeAll {
            Mock Get-AtpPolicyForO365     { [PSCustomObject]@{ Identity = 'Default' } }
            Mock Get-SafeAttachmentRule   { @() }
            Mock Get-SafeAttachmentPolicy {
                [PSCustomObject]@{ Name = 'Built-In Protection Policy'; Enable = $true; Action = 'Block' }
            }
        }
        It 'Reports the absent property as unassessed, not as a pass or a disabled setting' {
            $results = & $checkFile
            $globalResult = $results | Where-Object { $_.AffectedObject -eq 'Global Safe Attachments Settings' }
            $globalResult.Result | Should -Be 'NotApplicable'
            $globalResult.Error  | Should -Not -BeNullOrEmpty
            $globalResult.Finding | Should -Match 'not established'
        }
    }

    # Get-SafeAttachmentPolicy omits Action on a reduced object. The check tests it with
    # -eq 'Allow', so an absent Action is read as "not Allow" and never questioned.
    Context 'An enabled Safe Attachments policy omits the Action property' {
        BeforeAll {
            Mock Get-AtpPolicyForO365     { [PSCustomObject]@{ EnableATPForSPOTeamsODB = $true } }
            Mock Get-SafeAttachmentRule   { @() }
            Mock Get-SafeAttachmentPolicy {
                [PSCustomObject]@{ Name = 'Built-In Protection Policy'; Enable = $true }
            }
        }

        It 'Reports the missing Action as unassessed rather than a pass with an empty action' {
            $results = & $checkFile
            $policyResult = $results | Where-Object { $_.AffectedObject -match 'Built-In Protection Policy' }
            $policyResult | Should -Not -BeNullOrEmpty
            $policyResult.Result | Should -Be 'Warning'
            $policyResult.Finding | Should -Not -Match "enabled with action ''"
            $policyResult.Finding | Should -Match 'not established'
            $policyResult.Finding | Should -Match 'reported as unassessed rather than a pass'
        }
    }

    # Enable is read with -not, so an absent Enable is graded as a disabled policy.
    Context 'A Safe Attachments policy omits the Enable property' {
        BeforeAll {
            Mock Get-AtpPolicyForO365     { [PSCustomObject]@{ EnableATPForSPOTeamsODB = $true } }
            Mock Get-SafeAttachmentRule   { @() }
            Mock Get-SafeAttachmentPolicy {
                [PSCustomObject]@{ Name = 'Built-In Protection Policy'; Action = 'Block' }
            }
        }

        It 'Does not return Pass on a state it never observed' {
            $results = & $checkFile
            $policyResult = $results | Where-Object { $_.AffectedObject -match 'Built-In Protection Policy' }
            $policyResult.Result | Should -Not -Be 'Pass'
        }

        It 'States the property was not returned rather than asserting Safe Attachments is disabled' {
            $results = & $checkFile
            $policyResult = $results | Where-Object { $_.AffectedObject -match 'Built-In Protection Policy' }
            $policyResult.Result | Should -Be 'Warning'
            $policyResult.Finding | Should -Not -Match 'Safe Attachments is disabled'
            $policyResult.Finding | Should -Match 'not established'
            $policyResult.Finding | Should -Match 'reported as unassessed rather than a pass'
        }
    }
}
