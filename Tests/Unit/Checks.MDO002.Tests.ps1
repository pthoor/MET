BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METRuleScope.ps1"

    function Get-AtpPolicyForO365     { [CmdletBinding()] param() }
    function Get-SafeAttachmentRule   { [CmdletBinding()] param() }
    function Get-SafeAttachmentPolicy { [CmdletBinding()] param() }

    $checkFile = Join-Path $root 'Checks' 'MDO' 'MET-MDO002-SafeAttachments.ps1'
}

Describe 'MET-MDO002 Safe Attachments - per-policy Enable/Action assessment' {

    BeforeEach {
        Mock Get-AtpPolicyForO365 { [PSCustomObject]@{ EnableATPForSPOTeamsODB = $true } }
    }

    Context 'An enabled active policy omits the Action property' {
        BeforeAll {
            $rule = [PSCustomObject]@{ Name = 'Custom Policy'; SafeAttachmentPolicy = 'Custom Policy'; State = 'Enabled'; Priority = 0 }
            Mock Get-SafeAttachmentRule   { @($rule) }
            Mock Get-SafeAttachmentPolicy { [PSCustomObject]@{ Name = 'Custom Policy'; Enable = $true } }
        }

        It 'Returns Warning rather than a Pass that renders an empty action' {
            $results = @(& $checkFile)
            $policyResult = $results | Where-Object { $_.AffectedObject -match 'Custom Policy' }
            $policyResult | Should -Not -BeNullOrEmpty
            $policyResult.Result   | Should -Be 'Warning'
            $policyResult.Severity | Should -Be 'High'
            $policyResult.Finding  | Should -Not -Match "enabled with action ''"
            $policyResult.Error    | Should -Match 'Action'
        }
    }

    Context 'An active policy omits the Enable property' {
        BeforeAll {
            $rule = [PSCustomObject]@{ Name = 'Custom Policy'; SafeAttachmentPolicy = 'Custom Policy'; State = 'Enabled'; Priority = 0 }
            Mock Get-SafeAttachmentRule   { @($rule) }
            Mock Get-SafeAttachmentPolicy { [PSCustomObject]@{ Name = 'Custom Policy'; Action = 'Block' } }
        }

        It 'Returns Warning rather than asserting Safe Attachments is disabled' {
            $results = @(& $checkFile)
            $policyResult = $results | Where-Object { $_.AffectedObject -match 'Custom Policy' }
            $policyResult | Should -Not -BeNullOrEmpty
            $policyResult.Result   | Should -Be 'Warning'
            $policyResult.Finding  | Should -Not -Match 'Safe Attachments is disabled'
            $policyResult.Error    | Should -Match 'Enable'
        }
    }

    Context 'An active policy has Enable = $true and Action = Block' {
        BeforeAll {
            $rule = [PSCustomObject]@{ Name = 'Custom Policy'; SafeAttachmentPolicy = 'Custom Policy'; State = 'Enabled'; Priority = 0 }
            Mock Get-SafeAttachmentRule   { @($rule) }
            Mock Get-SafeAttachmentPolicy { [PSCustomObject]@{ Name = 'Custom Policy'; Enable = $true; Action = 'Block' } }
        }

        It 'Returns Pass with the unchanged sentence' {
            $results = @(& $checkFile)
            $policyResult = $results | Where-Object { $_.AffectedObject -match 'Custom Policy' }
            $policyResult.Result  | Should -Be 'Pass'
            $policyResult.Finding | Should -Match "Safe Attachments is enabled with action 'Block'"
        }
    }

    Context 'An active policy has Enable = $false' {
        BeforeAll {
            $rule = [PSCustomObject]@{ Name = 'Custom Policy'; SafeAttachmentPolicy = 'Custom Policy'; State = 'Enabled'; Priority = 0 }
            Mock Get-SafeAttachmentRule   { @($rule) }
            Mock Get-SafeAttachmentPolicy { [PSCustomObject]@{ Name = 'Custom Policy'; Enable = $false; Action = 'Block' } }
        }

        It 'Returns Fail with the unchanged sentence' {
            $results = @(& $checkFile)
            $policyResult = $results | Where-Object { $_.AffectedObject -match 'Custom Policy' }
            $policyResult.Result  | Should -Be 'Fail'
            $policyResult.Finding | Should -Match 'Safe Attachments is disabled'
        }
    }

    Context 'An active policy has Enable = $true and Action = Allow' {
        BeforeAll {
            $rule = [PSCustomObject]@{ Name = 'Custom Policy'; SafeAttachmentPolicy = 'Custom Policy'; State = 'Enabled'; Priority = 0 }
            Mock Get-SafeAttachmentRule   { @($rule) }
            Mock Get-SafeAttachmentPolicy { [PSCustomObject]@{ Name = 'Custom Policy'; Enable = $true; Action = 'Allow' } }
        }

        It 'Returns Fail with the unchanged sentence' {
            $results = @(& $checkFile)
            $policyResult = $results | Where-Object { $_.AffectedObject -match 'Custom Policy' }
            $policyResult.Result  | Should -Be 'Fail'
            $policyResult.Finding | Should -Match "Action is 'Allow' - attachments are not inspected"
        }
    }

    Context 'The Built-In Protection Policy omits the Action property' {
        BeforeAll {
            Mock Get-SafeAttachmentRule   { @() }
            Mock Get-SafeAttachmentPolicy { [PSCustomObject]@{ Name = 'Built-In Protection Policy'; Enable = $true } }
        }

        It 'Applies the same Warning treatment as a custom active policy' {
            $results = @(& $checkFile)
            $policyResult = $results | Where-Object { $_.AffectedObject -match 'Built-In Protection Policy' }
            $policyResult | Should -Not -BeNullOrEmpty
            $policyResult.Result  | Should -Be 'Warning'
            $policyResult.Finding | Should -Not -Match "enabled with action ''"
            $policyResult.Error   | Should -Match 'Action'
        }
    }

    Context 'An active policy has Action present but explicitly $null' {
        BeforeAll {
            $rule = [PSCustomObject]@{ Name = 'Custom Policy'; SafeAttachmentPolicy = 'Custom Policy'; State = 'Enabled'; Priority = 0 }
            Mock Get-SafeAttachmentRule   { @($rule) }
            Mock Get-SafeAttachmentPolicy { [PSCustomObject]@{ Name = 'Custom Policy'; Enable = $true; Action = $null } }
        }

        It 'Treats a present-but-null Action the same as an absent one' {
            $results = @(& $checkFile)
            $policyResult = $results | Where-Object { $_.AffectedObject -match 'Custom Policy' }
            $policyResult.Result  | Should -Be 'Warning'
            $policyResult.Finding | Should -Not -Match "enabled with action ''"
        }
    }

    Context 'An active policy has Enable present but explicitly $null' {
        BeforeAll {
            $rule = [PSCustomObject]@{ Name = 'Custom Policy'; SafeAttachmentPolicy = 'Custom Policy'; State = 'Enabled'; Priority = 0 }
            Mock Get-SafeAttachmentRule   { @($rule) }
            Mock Get-SafeAttachmentPolicy { [PSCustomObject]@{ Name = 'Custom Policy'; Enable = $null; Action = 'Block' } }
        }

        It 'Treats a present-but-null Enable the same as an absent one' {
            $results = @(& $checkFile)
            $policyResult = $results | Where-Object { $_.AffectedObject -match 'Custom Policy' }
            $policyResult.Result  | Should -Be 'Warning'
            $policyResult.Finding | Should -Not -Match 'Safe Attachments is disabled'
        }
    }
}
