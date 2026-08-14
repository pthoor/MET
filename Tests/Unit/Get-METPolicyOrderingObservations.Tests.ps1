BeforeAll { . (Join-Path $PSScriptRoot '..' '..' 'Private' 'Get-METPolicyOrderingObservations.ps1') }

Describe 'Get-METPolicyOrderingObservations' {
    It 'warns when a higher-priority custom catch-all shadows a specialized policy' {
        $summary = [PSCustomObject]@{ PolicyName='Finance'; Priority=1; PolicyType='Custom'; EffectiveRecipients=0; ShadowedRecipients=4; ShadowedBy=@("CustomCatchAll: 'General'") }
        $result = @(Get-METPolicyOrderingObservations -PolicySummaries @($summary))
        $result[0].Severity | Should -Be Warning
        $result[0].Message | Should -Match 'Move the catch-all below specialized custom policies'
    }

    It 'treats expected overlap with a higher scoped policy as informational' {
        $summary = [PSCustomObject]@{ PolicyName='General'; Priority=2; PolicyType='Custom'; EffectiveRecipients=10; ShadowedRecipients=2; ShadowedBy=@("Custom: 'Finance'") }
        $result = @(Get-METPolicyOrderingObservations -PolicySummaries @($summary))
        $result[0].Severity | Should -Be Info
    }

    It 'reports unassociated policy objects as informational' {
        $summary = [PSCustomObject]@{ PolicyName='Old'; PolicyType='Unassociated'; EffectiveRecipients=0 }
        $result = @(Get-METPolicyOrderingObservations -PolicySummaries @($summary))
        $result[0].Severity | Should -Be Info
        $result[0].Message | Should -Match 'no associated rule'
    }
}

Describe 'Get-METPolicyCoverageRecommendations' {
    It 'recommends a lowest-precedence catch-all when custom policies leave weak fallback coverage' {
        $resolution = [PSCustomObject]@{
            RecipientAssignments = @([PSCustomObject]@{ Recipient='a@contoso.com'; PolicyName='Default'; PolicyType='Default' })
            PolicySummaries = @([PSCustomObject]@{ PolicyName='Finance'; PolicyType='Custom'; State='Enabled' })
        }
        $result = @(Get-METPolicyCoverageRecommendations -Resolution $resolution -IssuesByPolicy @{ Default=@('Below baseline') })
        $result[0] | Should -Match 'catch-all'
        $result[0] | Should -Match 'after all specialized custom policies'
    }

    It 'does not recommend a catch-all when fallback coverage meets the baseline' {
        $resolution = [PSCustomObject]@{ RecipientAssignments=@([PSCustomObject]@{PolicyName='Default';PolicyType='Default'}); PolicySummaries=@() }
        @(Get-METPolicyCoverageRecommendations -Resolution $resolution -IssuesByPolicy @{ Default=@() }) | Should -HaveCount 0
    }
}
