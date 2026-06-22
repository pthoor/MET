BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . (Join-Path $root 'Private' 'New-METCheckResult.ps1')
    . (Join-Path $root 'Private' 'Get-METCheckWeight.ps1')
    . (Join-Path $root 'Private' 'Expand-METGroupMembership.ps1')
    . (Join-Path $root 'Private' 'Expand-METRuleRecipients.ps1')
    . (Join-Path $root 'Private' 'Resolve-METPresetPolicy.ps1')
    . (Join-Path $root 'Private' 'Resolve-METCoverageMatrix.ps1')

    # Stubs for EXO/Graph cmdlets — replaced by Pester mocks in each Context block.
    function Get-EOPProtectionPolicyRule  { throw 'not mocked' }
    function Get-ATPProtectionPolicyRule  { throw 'not mocked' }
    function Get-HostedContentFilterRule  { throw 'not mocked' }
    function Get-SafeLinksRule            { throw 'not mocked' }
    function Get-AntiPhishRule            { throw 'not mocked' }
    function Get-MgGroup                  { throw 'not mocked' }
    function Get-MgGroupTransitiveMember  { throw 'not mocked' }
    function Get-DistributionGroupMember  { throw 'not mocked' }

    # Minimal rule stub — only the fields Expand-METRuleRecipients reads.
    function New-RuleStub {
        param([string[]]$SentTo, [string]$State = 'Enabled')
        [PSCustomObject]@{
            State                   = $State
            SentTo                  = $SentTo
            SentToMemberOf          = $null
            RecipientDomainIs       = $null
            ExceptIfSentTo          = $null
            ExceptIfSentToMemberOf  = $null
            ExceptIfRecipientDomainIs = $null
        }
    }
}

Describe 'Resolve-METCoverageMatrix' {

    Context 'All mailboxes in Strict preset (EOP and ATP)' {
        BeforeEach {
            Mock Resolve-METPresetPolicy {
                param($Tier, $Stack)
                [PSCustomObject]@{
                    Tier    = $Tier
                    Stack   = $Stack
                    Enabled = ($Tier -eq 'Strict')
                    Rule    = if ($Tier -eq 'Strict') { New-RuleStub -SentTo @('alice@contoso.com','bob@contoso.com') } else { $null }
                }
            }
            Mock Get-HostedContentFilterRule { @() }
            Mock Get-SafeLinksRule           { @() }
            Mock Get-AntiPhishRule           { @() }
        }

        It 'Assigns Strict EopTier and Strict AtpTier to all mailboxes' {
            $matrix = Resolve-METCoverageMatrix `
                -AllMailboxes @('alice@contoso.com','bob@contoso.com') `
                -GroupCache @{}

            $matrix['alice@contoso.com'].EopTier | Should -Be 'Strict'
            $matrix['alice@contoso.com'].AtpTier | Should -Be 'Strict'
            $matrix['bob@contoso.com'].EopTier   | Should -Be 'Strict'
            $matrix['bob@contoso.com'].AtpTier   | Should -Be 'Strict'
        }
    }

    Context 'EOP preset covers all; ATP preset covers none (condition divergence)' {
        BeforeEach {
            Mock Resolve-METPresetPolicy {
                param($Tier, $Stack)
                $strictAddrs = @('alice@contoso.com','bob@contoso.com')
                if ($Tier -eq 'Strict' -and $Stack -eq 'EOP') {
                    [PSCustomObject]@{ Tier=$Tier; Stack=$Stack; Enabled=$true;  Rule=(New-RuleStub -SentTo $strictAddrs) }
                } else {
                    [PSCustomObject]@{ Tier=$Tier; Stack=$Stack; Enabled=$false; Rule=$null }
                }
            }
            Mock Get-HostedContentFilterRule { @() }
            Mock Get-SafeLinksRule           { @() }
            Mock Get-AntiPhishRule           { @() }
        }

        It 'EopTier is Strict and AtpTier is BuiltIn — detected as ATP gap' {
            $matrix = Resolve-METCoverageMatrix `
                -AllMailboxes @('alice@contoso.com','bob@contoso.com') `
                -GroupCache @{}

            $matrix['alice@contoso.com'].EopTier | Should -Be 'Strict'
            $matrix['alice@contoso.com'].AtpTier | Should -Be 'BuiltIn'
        }
    }

    Context 'No preset; some mailboxes in custom EOP policy, some in custom ATP policy' {
        BeforeEach {
            Mock Resolve-METPresetPolicy {
                param($Tier, $Stack)
                [PSCustomObject]@{ Tier=$Tier; Stack=$Stack; Enabled=$false; Rule=$null }
            }
            Mock Get-HostedContentFilterRule {
                @(New-RuleStub -SentTo @('alice@contoso.com') | Add-Member -NotePropertyName Name -NotePropertyValue 'CustomEOP' -PassThru |
                  Add-Member -NotePropertyName Priority -NotePropertyValue 0 -PassThru)
            }
            Mock Get-SafeLinksRule {
                @(New-RuleStub -SentTo @('bob@contoso.com') | Add-Member -NotePropertyName Priority -NotePropertyValue 0 -PassThru)
            }
            Mock Get-AntiPhishRule { @() }
        }

        It 'alice gets Custom EopTier; bob stays Default' {
            $matrix = Resolve-METCoverageMatrix `
                -AllMailboxes @('alice@contoso.com','bob@contoso.com','carol@contoso.com') `
                -GroupCache @{}

            $matrix['alice@contoso.com'].EopTier | Should -Be 'Custom'
            $matrix['bob@contoso.com'].EopTier   | Should -Be 'Default'
            $matrix['carol@contoso.com'].EopTier | Should -Be 'Default'
        }

        It 'bob gets Custom AtpTier; alice stays BuiltIn' {
            $matrix = Resolve-METCoverageMatrix `
                -AllMailboxes @('alice@contoso.com','bob@contoso.com','carol@contoso.com') `
                -GroupCache @{}

            $matrix['bob@contoso.com'].AtpTier   | Should -Be 'Custom'
            $matrix['alice@contoso.com'].AtpTier | Should -Be 'BuiltIn'
            $matrix['carol@contoso.com'].AtpTier | Should -Be 'BuiltIn'
        }
    }

    Context 'Standard preset covers all mailboxes; Strict covers none' {
        BeforeEach {
            $allAddrs = @('alice@contoso.com','bob@contoso.com')
            Mock Resolve-METPresetPolicy {
                param($Tier, $Stack)
                if ($Tier -eq 'Standard') {
                    [PSCustomObject]@{ Tier=$Tier; Stack=$Stack; Enabled=$true; Rule=(New-RuleStub -SentTo $allAddrs) }
                } else {
                    [PSCustomObject]@{ Tier=$Tier; Stack=$Stack; Enabled=$false; Rule=$null }
                }
            }
            Mock Get-HostedContentFilterRule { @() }
            Mock Get-SafeLinksRule           { @() }
            Mock Get-AntiPhishRule           { @() }
        }

        It 'EopTier and AtpTier are both Standard' {
            $matrix = Resolve-METCoverageMatrix `
                -AllMailboxes @('alice@contoso.com','bob@contoso.com') `
                -GroupCache @{}

            $matrix['alice@contoso.com'].EopTier | Should -Be 'Standard'
            $matrix['alice@contoso.com'].AtpTier | Should -Be 'Standard'
        }
    }

    Context 'Strict preset wins over Standard when a mailbox is in both' {
        BeforeEach {
            $allAddrs = @('alice@contoso.com')
            Mock Resolve-METPresetPolicy {
                param($Tier, $Stack)
                # Both Strict and Standard include alice — Strict should win.
                [PSCustomObject]@{ Tier=$Tier; Stack=$Stack; Enabled=$true; Rule=(New-RuleStub -SentTo $allAddrs) }
            }
            Mock Get-HostedContentFilterRule { @() }
            Mock Get-SafeLinksRule           { @() }
            Mock Get-AntiPhishRule           { @() }
        }

        It 'EopTier and AtpTier are Strict (not Standard)' {
            $matrix = Resolve-METCoverageMatrix -AllMailboxes @('alice@contoso.com') -GroupCache @{}
            $matrix['alice@contoso.com'].EopTier | Should -Be 'Strict'
            $matrix['alice@contoso.com'].AtpTier | Should -Be 'Strict'
        }
    }

    Context 'Strict preset configured for all recipients (no include conditions — catch-all rule)' {
        BeforeEach {
            # Rule with no SentTo/SentToMemberOf/RecipientDomainIs — matches all recipients
            $catchAllRule = New-RuleStub
            Mock Resolve-METPresetPolicy {
                param($Tier, $Stack)
                [PSCustomObject]@{ Tier=$Tier; Stack=$Stack; Enabled=($Tier -eq 'Strict'); Rule=if ($Tier -eq 'Strict') { $catchAllRule } else { $null } }
            }
            Mock Get-HostedContentFilterRule { @() }
            Mock Get-SafeLinksRule           { @() }
            Mock Get-AntiPhishRule           { @() }
        }

        It 'All mailboxes get Strict EopTier and Strict AtpTier' {
            $mbxs = @('alice@contoso.com','bob@contoso.com','carol@contoso.com')
            $matrix = Resolve-METCoverageMatrix -AllMailboxes $mbxs -GroupCache @{}

            foreach ($m in $mbxs) {
                $matrix[$m].EopTier | Should -Be 'Strict'
                $matrix[$m].AtpTier | Should -Be 'Strict'
            }
        }
    }

    Context 'Empty mailbox list' {
        BeforeEach {
            Mock Resolve-METPresetPolicy {
                param($Tier, $Stack)
                [PSCustomObject]@{ Tier=$Tier; Stack=$Stack; Enabled=$false; Rule=$null }
            }
            Mock Get-HostedContentFilterRule { @() }
            Mock Get-SafeLinksRule           { @() }
            Mock Get-AntiPhishRule           { @() }
        }

        It 'Returns an empty hashtable' {
            $matrix = Resolve-METCoverageMatrix -AllMailboxes @() -GroupCache @{}
            $matrix.Count | Should -Be 0
        }
    }

    Context 'Anti-Phish rule promotes ATP tier when Safe Links has no match' {
        BeforeEach {
            Mock Resolve-METPresetPolicy {
                param($Tier, $Stack)
                [PSCustomObject]@{ Tier=$Tier; Stack=$Stack; Enabled=$false; Rule=$null }
            }
            Mock Get-HostedContentFilterRule { @() }
            Mock Get-SafeLinksRule           { @() }
            Mock Get-AntiPhishRule {
                @(New-RuleStub -SentTo @('alice@contoso.com') |
                  Add-Member -NotePropertyName Name     -NotePropertyValue 'CustomAP'  -PassThru |
                  Add-Member -NotePropertyName Priority -NotePropertyValue 0           -PassThru)
            }
        }

        It 'alice AtpTier is Custom from Anti-Phish rule' {
            $matrix = Resolve-METCoverageMatrix -AllMailboxes @('alice@contoso.com') -GroupCache @{}
            $matrix['alice@contoso.com'].AtpTier | Should -Be 'Custom'
        }
    }
}
