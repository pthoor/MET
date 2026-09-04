BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . (Join-Path $root 'Private' 'Expand-METGroupMembership.ps1')
    . (Join-Path $root 'Private' 'Find-METRuleContradictions.ps1')

    # Group expansion is exercised through a pre-populated cache, which
    # Expand-METGroupMembership returns from before it reaches any EXO or Graph
    # cmdlet, so these stubs only guard against an unintended live call.
    function Get-MgGroup                 { throw 'not mocked' }
    function Get-MgGroupTransitiveMember { throw 'not mocked' }
    function Get-DistributionGroupMember { throw 'not mocked' }
    function Get-UnifiedGroupLinks       { throw 'not mocked' }

    function New-ContradictionRuleStub {
        param(
            [string]   $Name = 'Rule',
            [string]   $State = 'Enabled',
            [int]      $Priority = 0,
            [string[]] $SentTo,
            [string[]] $SentToMemberOf,
            [string[]] $RecipientDomainIs,
            [string[]] $ExceptIfSentTo,
            [string[]] $ExceptIfSentToMemberOf,
            [string[]] $ExceptIfRecipientDomainIs
        )
        [PSCustomObject]@{
            Name                      = $Name
            State                     = $State
            Priority                  = $Priority
            SentTo                    = $SentTo
            SentToMemberOf            = $SentToMemberOf
            RecipientDomainIs         = $RecipientDomainIs
            ExceptIfSentTo            = $ExceptIfSentTo
            ExceptIfSentToMemberOf    = $ExceptIfSentToMemberOf
            ExceptIfRecipientDomainIs = $ExceptIfRecipientDomainIs
        }
    }
}

Describe 'Find-METRuleContradictions' {

    Context 'A mailbox included and excepted by the same rule' {

        It 'Reports the contradiction with both reasons and the rule identity' {
            $rule = New-ContradictionRuleStub -Name 'Strict Preset Security Policy' -Priority 3 `
                -SentTo @('alice@contoso.com', 'bob@contoso.com') `
                -ExceptIfSentTo @('alice@contoso.com')

            $found = @(Find-METRuleContradictions -Rules @($rule) `
                -AllMailboxes @('alice@contoso.com', 'bob@contoso.com') `
                -GroupCache @{} -PolicyType 'EOP Preset')

            $found.Count | Should -Be 1
            $found[0].PolicyType    | Should -Be 'EOP Preset'
            $found[0].RuleName      | Should -Be 'Strict Preset Security Policy'
            $found[0].Priority      | Should -Be 3
            $found[0].Address       | Should -Be 'alice@contoso.com'
            $found[0].IncludeReason | Should -Be 'directly listed in SentTo'
            $found[0].ExcludeReason | Should -Be 'directly listed in ExceptIfSentTo'
        }

        It 'Reports a mailbox included by domain and excepted by name' {
            $rule = New-ContradictionRuleStub -Name 'Domain Rule' `
                -RecipientDomainIs @('contoso.com') `
                -ExceptIfSentTo @('bob@contoso.com')

            $found = @(Find-METRuleContradictions -Rules @($rule) `
                -AllMailboxes @('alice@contoso.com', 'bob@contoso.com') `
                -GroupCache @{} -PolicyType 'Anti-Spam')

            $found.Count | Should -Be 1
            $found[0].Address       | Should -Be 'bob@contoso.com'
            $found[0].IncludeReason | Should -Be "matched by included domain 'contoso.com'"
        }

        It 'Reports a mailbox included by group membership and excepted by group membership' {
            $cache = @{
                'all@contoso.com'   = @('alice@contoso.com', 'bob@contoso.com')
                'execs@contoso.com' = @('alice@contoso.com')
            }
            $rule = New-ContradictionRuleStub -Name 'Group Rule' `
                -SentToMemberOf @('all@contoso.com') `
                -ExceptIfSentToMemberOf @('execs@contoso.com')

            $found = @(Find-METRuleContradictions -Rules @($rule) `
                -AllMailboxes @('alice@contoso.com', 'bob@contoso.com') `
                -GroupCache $cache -PolicyType 'MDO Preset')

            $found.Count | Should -Be 1
            $found[0].Address       | Should -Be 'alice@contoso.com'
            $found[0].IncludeReason | Should -Be "member of included group 'all@contoso.com'"
            $found[0].ExcludeReason | Should -Be "member of excluded group 'execs@contoso.com'"
        }

        It 'Returns nothing when the rule has includes but no exceptions' {
            $rule = New-ContradictionRuleStub -Name 'Clean Rule' -SentTo @('alice@contoso.com')

            $found = @(Find-METRuleContradictions -Rules @($rule) `
                -AllMailboxes @('alice@contoso.com') `
                -GroupCache @{} -PolicyType 'Safe Links')

            $found.Count | Should -Be 0
        }
    }

    Context 'Rules the helper documents as out of scope' {

        It 'Skips a catch-all rule that has exceptions but no include conditions' {
            $rule = New-ContradictionRuleStub -Name 'Catch-All' `
                -ExceptIfSentTo @('alice@contoso.com') `
                -ExceptIfRecipientDomainIs @('contoso.com')

            $found = @(Find-METRuleContradictions -Rules @($rule) `
                -AllMailboxes @('alice@contoso.com', 'bob@contoso.com') `
                -GroupCache @{} -PolicyType 'Anti-Phishing')

            $found.Count | Should -Be 0
        }

        It 'Skips a rule that is not Enabled even when it contradicts itself' {
            $rule = New-ContradictionRuleStub -Name 'Disabled Rule' -State 'Disabled' `
                -SentTo @('alice@contoso.com') `
                -ExceptIfSentTo @('alice@contoso.com')

            $found = @(Find-METRuleContradictions -Rules @($rule) `
                -AllMailboxes @('alice@contoso.com') `
                -GroupCache @{} -PolicyType 'Safe Attachments')

            $found.Count | Should -Be 0
        }
    }

    Context 'A mailbox list containing an entry with no domain part' {

        BeforeAll {
            $script:domainRule = New-ContradictionRuleStub -Name 'Domain Rule' `
                -RecipientDomainIs @('contoso.com') `
                -ExceptIfSentTo @('bob@contoso.com')
        }

        It 'Does not throw when an entry has no @ separator' {
            { Find-METRuleContradictions -Rules @($script:domainRule) `
                -AllMailboxes @('alice@contoso.com', 'DiscoverySearchMailbox', 'bob@contoso.com') `
                -GroupCache @{} -PolicyType 'Anti-Spam' } | Should -Not -Throw
        }

        It 'Still evaluates the well-formed entries around a malformed one' {
            $found = @(Find-METRuleContradictions -Rules @($script:domainRule) `
                -AllMailboxes @('alice@contoso.com', 'DiscoverySearchMailbox', 'bob@contoso.com') `
                -GroupCache @{} -PolicyType 'Anti-Spam')

            $found.Count | Should -Be 1
            $found[0].Address | Should -Be 'bob@contoso.com'
        }

        It 'Does not throw when an entry has an empty domain part' {
            { Find-METRuleContradictions -Rules @($script:domainRule) `
                -AllMailboxes @('alice@contoso.com', 'orphaned@', 'bob@contoso.com') `
                -GroupCache @{} -PolicyType 'Anti-Spam' } | Should -Not -Throw
        }

        It 'Never matches a domain condition against an entry with no domain part' {
            $rule = New-ContradictionRuleStub -Name 'Empty Domain Rule' `
                -RecipientDomainIs @('contoso.com') `
                -ExceptIfRecipientDomainIs @('contoso.com')

            $found = @(Find-METRuleContradictions -Rules @($rule) `
                -AllMailboxes @('DiscoverySearchMailbox', 'orphaned@', 'bob@contoso.com') `
                -GroupCache @{} -PolicyType 'Anti-Spam')

            $found.Count | Should -Be 1
            $found[0].Address | Should -Be 'bob@contoso.com'
        }

        It 'Does not record a skipped entry as a retrieval error' {
            $retrievalErrors = [System.Collections.Generic.List[string]]::new()

            $null = Find-METRuleContradictions -Rules @($script:domainRule) `
                -AllMailboxes @('alice@contoso.com', 'DiscoverySearchMailbox') `
                -GroupCache @{} -PolicyType 'Anti-Spam' -RetrievalErrors $retrievalErrors

            $retrievalErrors.Count | Should -Be 0
        }
    }
}
