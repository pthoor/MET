BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . (Join-Path $root 'Private' 'Expand-METGroupMembership.ps1')
    . (Join-Path $root 'Private' 'Expand-METRuleRecipients.ps1')
    . (Join-Path $root 'Private' 'Resolve-METSafeLinksEffectivePolicy.ps1')

    function New-SafeLinksRuleStub {
        param(
            [string] $Name,
            [string] $PolicyName,
            [int] $Priority = 0,
            [string] $State = 'Enabled',
            [string[]] $SentTo,
            [string[]] $Groups,
            [string[]] $Domains,
            [string[]] $ExceptSentTo,
            [string[]] $ExceptGroups,
            [string[]] $ExceptDomains
        )
        [PSCustomObject]@{
            Name = $Name; SafeLinksPolicy = $PolicyName; Priority = $Priority; State = $State
            SentTo = $SentTo; SentToMemberOf = $Groups; RecipientDomainIs = $Domains
            ExceptIfSentTo = $ExceptSentTo; ExceptIfSentToMemberOf = $ExceptGroups
            ExceptIfRecipientDomainIs = $ExceptDomains
        }
    }
}

Describe 'Expand-METRuleRecipients matching semantics' {
    BeforeEach {
        Mock Expand-METGroupMembership {
            if ($Identity -eq 'sales') { @('alice@sub.contoso.com', 'carol@other.com') } else { @() }
        }
    }

    It 'uses OR within a condition type and includes subdomains case-insensitively' {
        $rule = New-SafeLinksRuleStub -Domains @('CONTOSO.COM', 'fabrikam.com')
        $actual = @(Expand-METRuleRecipients -Rule $rule -AllMailboxes @(
            'alice@sub.contoso.com', 'bob@FABRIKAM.COM', 'carol@other.com'
        ) -GroupCache @{})
        $actual | Should -HaveCount 2
        $actual | Should -Contain 'alice@sub.contoso.com'
        $actual | Should -Contain 'bob@FABRIKAM.COM'
    }

    It 'uses AND across different inclusion condition types' {
        $rule = New-SafeLinksRuleStub -Groups @('sales') -Domains @('contoso.com')
        $actual = @(Expand-METRuleRecipients -Rule $rule -AllMailboxes @(
            'alice@sub.contoso.com', 'bob@contoso.com', 'carol@other.com'
        ) -GroupCache @{})
        $actual | Should -HaveCount 1
        $actual[0] | Should -Be 'alice@sub.contoso.com'
    }

    It 'uses OR across exception types' {
        $rule = New-SafeLinksRuleStub -ExceptSentTo @('bob@contoso.com') -ExceptDomains @('other.com')
        $actual = @(Expand-METRuleRecipients -Rule $rule -AllMailboxes @(
            'alice@contoso.com', 'bob@contoso.com', 'carol@sub.other.com'
        ) -GroupCache @{})
        $actual | Should -HaveCount 1
        $actual[0] | Should -Be 'alice@contoso.com'
    }
}

Describe 'Resolve-METSafeLinksEffectivePolicy' {
    It 'assigns presets before priority-ordered custom policies and preserves zero-recipient summaries' {
        $mailboxes = @('strict@contoso.com', 'custom@contoso.com', 'fallback@other.com')
        $strictRule = New-SafeLinksRuleStub -Name 'Strict Preset Security Policy' -SentTo @('strict@contoso.com')
        $customRule = New-SafeLinksRuleStub -Name 'CatchAllRule' -PolicyName 'CatchAllPolicy' -Priority 0
        $shadowedRule = New-SafeLinksRuleStub -Name 'ShadowedRule' -PolicyName 'ShadowedPolicy' -Priority 1
        $policies = @(
            [PSCustomObject]@{ Name = 'Strict Preset Security Policy1707729536596' }
            [PSCustomObject]@{ Name = 'CatchAllPolicy' }
            [PSCustomObject]@{ Name = 'ShadowedPolicy' }
            [PSCustomObject]@{ Name = 'Built-In Protection Policy' }
        )

        $result = Resolve-METSafeLinksEffectivePolicy -AllMailboxes $mailboxes -GroupCache @{} `
            -Rules @($customRule, $shadowedRule) -Policies $policies -PresetRules @($strictRule)

        ($result.RecipientAssignments | Where-Object Recipient -eq 'strict@contoso.com').PolicyName |
            Should -Be 'Strict Preset Security Policy1707729536596'
        ($result.RecipientAssignments | Where-Object Recipient -eq 'custom@contoso.com').PolicyName |
            Should -Be 'CatchAllPolicy'
        ($result.PolicySummaries | Where-Object PolicyName -eq 'ShadowedPolicy').EffectiveRecipients |
            Should -Be 0
        ($result.PolicySummaries | Where-Object PolicyName -eq 'CatchAllPolicy').ScopeDescription |
            Should -Match '^Catch-all'
    }

    It 'records an enabled rule whose referenced policy is missing' {
        $errors = [System.Collections.Generic.List[string]]::new()
        $rule = New-SafeLinksRuleStub -Name 'OrphanRule' -PolicyName 'MissingPolicy'
        $null = Resolve-METSafeLinksEffectivePolicy -AllMailboxes @('a@contoso.com') -GroupCache @{} `
            -Rules @($rule) -Policies @() -PresetRules @() -RetrievalErrors $errors
        $errors -join ' ' | Should -Match 'MissingPolicy'
    }

    It 'discloses that enabled evaluation policy precedence is not modeled' {
        $errors = [System.Collections.Generic.List[string]]::new()
        $evaluation = New-SafeLinksRuleStub -Name 'ATP Evaluation Policy'
        $null = Resolve-METSafeLinksEffectivePolicy -AllMailboxes @('a@contoso.com') -GroupCache @{} `
            -Rules @() -Policies @() -PresetRules @($evaluation) -RetrievalErrors $errors
        $errors -join ' ' | Should -Match 'evaluation policy'
    }
}
