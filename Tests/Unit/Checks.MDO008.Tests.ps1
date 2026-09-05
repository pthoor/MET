BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"
    . "$root/Private/Resolve-METPresetPolicy.ps1"
    . "$root/Private/Resolve-METCoverageMatrix.ps1"
    . "$root/Private/Expand-METRuleRecipients.ps1"
    . "$root/Private/Expand-METGroupMembership.ps1"
    . "$root/Private/Find-METRuleContradictions.ps1"
    . "$root/Private/Get-METAssessableMailboxes.ps1"

    function Get-EXOMailbox              { [CmdletBinding()] param([string]$ResultSize,[string]$PropertySets,[string[]]$Properties,[string]$Filter) }
    function Get-EOPProtectionPolicyRule { [CmdletBinding()] param([string]$Identity) }
    function Get-ATPProtectionPolicyRule { [CmdletBinding()] param([string]$Identity) }
    function Get-HostedContentFilterRule { [CmdletBinding()] param() }
    function Get-SafeLinksRule           { [CmdletBinding()] param() }
    function Get-SafeAttachmentRule      { [CmdletBinding()] param() }
    function Get-AntiPhishRule           { [CmdletBinding()] param() }
    function Get-MgGroup                 { [CmdletBinding()] param([string]$Filter,[int]$Top) }
    function Get-MgGroupTransitiveMember { [CmdletBinding()] param([string]$GroupId,[switch]$All) }
    function Get-DistributionGroupMember { [CmdletBinding()] param([string]$Identity,[string]$ResultSize) }
    function Get-UnifiedGroupLinks       { [CmdletBinding()] param([string]$Identity,[string]$LinkType,[string]$ResultSize) }

    $checkFile = Join-Path $root 'Checks' 'MDO' 'MET-MDO008-PresetPolicyCoverage.ps1'

    function New-METTestMailboxes {
        param([int]$Count, [string]$Domain = 'contoso.com')
        1..$Count | ForEach-Object {
            [PSCustomObject]@{
                PrimarySmtpAddress   = "user$_@$Domain"
                RecipientTypeDetails = 'UserMailbox'
            }
        }
    }

    function New-METTestPresetRule {
        param(
            [string]   $Tier = 'Strict',
            [string[]] $SentTo,
            [string[]] $RecipientDomainIs
        )
        $rule = [PSCustomObject]@{
            Name                   = "$Tier Preset Security Policy"
            State                  = 'Enabled'
            Priority               = 0
            SentTo                 = $SentTo
            SentToMemberOf         = $null
            RecipientDomainIs      = $RecipientDomainIs
            ExceptIfSentTo         = $null
            ExceptIfSentToMemberOf = $null
        }
        $rule
    }
}

Describe 'MET-MDO008 Preset Policy Coverage' {
    BeforeEach {
        # Graph and Exchange group expansion are unavailable by default; no fixture
        # below relies on a group unless it mocks these explicitly.
        Mock Get-MgGroup                 { throw 'Graph not available' }
        Mock Get-MgGroupTransitiveMember { throw 'Graph not available' }
        Mock Get-HostedContentFilterRule { @() }
        Mock Get-SafeLinksRule           { @() }
        Mock Get-SafeAttachmentRule      { @() }
        Mock Get-AntiPhishRule           { @() }
        $METContext = @{}
    }

    Context 'Every mailbox is covered by both the EOP and MDO Strict preset' {
        BeforeEach {
            Mock Get-EXOMailbox { New-METTestMailboxes -Count 10 }
            Mock Get-EOPProtectionPolicyRule { @(New-METTestPresetRule -Tier Strict -RecipientDomainIs 'contoso.com') }
            Mock Get-ATPProtectionPolicyRule { @(New-METTestPresetRule -Tier Strict -RecipientDomainIs 'contoso.com') }
        }

        It 'Returns a single Pass result' {
            $results = @(& $checkFile $METContext)
            $results.Count | Should -Be 1
            $results[0].CheckId  | Should -Be 'MET-MDO008'
            $results[0].Category | Should -Be 'MDO'
            $results[0].Name     | Should -Be 'Preset Policy Coverage'
            $results[0].Result   | Should -Be 'Pass'
            $results[0].Severity | Should -Be 'High'
            $results[0].Error    | Should -BeNullOrEmpty
        }

        It 'Names the tier distribution actually observed, not just a clean verdict' {
            $results = @(& $checkFile $METContext)
            $results[0].AffectedObject | Should -Be 'Tenant (10 mailboxes)'
            $results[0].Finding | Should -Match 'All 10 mailboxes'
            $results[0].Finding | Should -Match 'EOP: Strict: 10 \(100%\)'
            $results[0].Finding | Should -Match 'MDO: Strict: 10 \(100%\)'
        }

        It 'Caches the coverage matrix for later checks only when the data was complete' {
            $null = & $checkFile $METContext
            $METContext.CoverageMatrix | Should -Not -BeNullOrEmpty
            $METContext.CoverageMatrix['user1@contoso.com'].EopTier | Should -Be 'Strict'
            $METContext.CoverageMatrix['user1@contoso.com'].AtpTier | Should -Be 'Strict'
        }
    }

    Context 'More than 10 % of mailboxes sit on the EOP Default policy' {
        BeforeEach {
            Mock Get-EXOMailbox { New-METTestMailboxes -Count 10 }
            Mock Get-EOPProtectionPolicyRule {
                @(New-METTestPresetRule -Tier Strict -SentTo @(1..8 | ForEach-Object { "user$_@contoso.com" }))
            }
            Mock Get-ATPProtectionPolicyRule { @(New-METTestPresetRule -Tier Strict -RecipientDomainIs 'contoso.com') }
        }

        It 'Fails at High severity and names the uncovered mailboxes' {
            $results = @(& $checkFile $METContext)
            $eop = $results | Where-Object Name -eq 'Preset Policy Coverage - EOP Gap'
            $eop | Should -Not -BeNullOrEmpty
            $eop.Result   | Should -Be 'Fail'
            $eop.Severity | Should -Be 'High'
            $eop.AffectedObject | Should -Be '2 of 10 mailboxes'
            $eop.Finding | Should -Match '2 mailbox\(es\) \(20%\)'
            $eop.Finding | Should -Match 'EOP Default policy'
            $eop.Finding | Should -Match 'user9@contoso\.com'
            $eop.Finding | Should -Match 'user10@contoso\.com'
        }

        It 'Emits no MDO gap result because the MDO preset covers everyone' {
            $results = @(& $checkFile $METContext)
            ($results | Where-Object Name -eq 'Preset Policy Coverage - MDO Gap') | Should -BeNullOrEmpty
            ($results | Where-Object Result -eq 'Pass') | Should -BeNullOrEmpty
        }
    }

    Context 'Exactly 10 % of mailboxes sit on the EOP Default policy' {
        BeforeEach {
            Mock Get-EXOMailbox { New-METTestMailboxes -Count 20 }
            Mock Get-EOPProtectionPolicyRule {
                @(New-METTestPresetRule -Tier Strict -SentTo @(1..18 | ForEach-Object { "user$_@contoso.com" }))
            }
            Mock Get-ATPProtectionPolicyRule { @(New-METTestPresetRule -Tier Strict -RecipientDomainIs 'contoso.com') }
        }

        It 'Warns rather than fails when the gap is within the 10 % threshold' {
            $results = @(& $checkFile $METContext)
            $eop = $results | Where-Object Name -eq 'Preset Policy Coverage - EOP Gap'
            $eop.Result   | Should -Be 'Warning'
            $eop.Severity | Should -Be 'High'
            $eop.AffectedObject | Should -Be '2 of 20 mailboxes'
            $eop.Finding | Should -Match '2 mailbox\(es\) \(10%\)'
        }
    }

    Context 'Mailboxes have no MDO policy beyond Built-in Protection' {
        BeforeEach {
            Mock Get-EXOMailbox { New-METTestMailboxes -Count 10 }
            Mock Get-EOPProtectionPolicyRule { @(New-METTestPresetRule -Tier Strict -RecipientDomainIs 'contoso.com') }
            Mock Get-ATPProtectionPolicyRule { @() }
        }

        It 'Fails at High severity naming the Built-in Protection baseline' {
            $results = @(& $checkFile $METContext)
            $atp = $results | Where-Object Name -eq 'Preset Policy Coverage - MDO Gap'
            $atp | Should -Not -BeNullOrEmpty
            $atp.Result   | Should -Be 'Fail'
            $atp.Severity | Should -Be 'High'
            $atp.AffectedObject | Should -Be '10 of 10 mailboxes'
            $atp.Finding | Should -Match 'Safe Links, Safe Attachments, or Anti-Phish'
            $atp.Finding | Should -Match 'Built-in Protection baseline'
            $atp.Finding | Should -Match "user1@contoso\.com`: EOP=Strict"
        }
    }

    Context 'EOP tier outranks the MDO tier for the same mailboxes' {
        BeforeEach {
            Mock Get-EXOMailbox { New-METTestMailboxes -Count 10 }
            Mock Get-EOPProtectionPolicyRule { @(New-METTestPresetRule -Tier Strict   -RecipientDomainIs 'contoso.com') }
            Mock Get-ATPProtectionPolicyRule { @(New-METTestPresetRule -Tier Standard -RecipientDomainIs 'contoso.com') }
        }

        It 'Warns at Medium severity and names both diverged tiers' {
            $results = @(& $checkFile $METContext)
            $mismatch = $results | Where-Object Name -eq 'Preset Policy Coverage - EOP/MDO Mismatch'
            $mismatch | Should -Not -BeNullOrEmpty
            $mismatch.Result   | Should -Be 'Warning'
            $mismatch.Severity | Should -Be 'Medium'
            $mismatch.AffectedObject | Should -Be '10 of 10 mailboxes'
            $mismatch.Finding | Should -Match 'higher EOP protection tier than their MDO protection tier'
            $mismatch.Finding | Should -Match "EOP=Strict via 'Strict Preset Security Policy' / ATP=Standard via 'Standard Preset Security Policy'"
        }

        It 'Does not also report a coverage gap for mailboxes that are covered by both stacks' {
            $results = @(& $checkFile $METContext)
            ($results | Where-Object Name -match 'Gap') | Should -BeNullOrEmpty
        }
    }

    Context 'A rule includes and excepts the same recipient' {
        BeforeEach {
            Mock Get-EXOMailbox { New-METTestMailboxes -Count 10 }
            Mock Get-EOPProtectionPolicyRule { @(New-METTestPresetRule -Tier Strict -RecipientDomainIs 'contoso.com') }
            Mock Get-ATPProtectionPolicyRule { @(New-METTestPresetRule -Tier Strict -RecipientDomainIs 'contoso.com') }
            Mock Get-SafeAttachmentRule {
                @([PSCustomObject]@{
                    Name                   = 'SA - Finance'
                    State                  = 'Enabled'
                    Priority               = 3
                    SentTo                 = @('user1@contoso.com')
                    SentToMemberOf         = $null
                    RecipientDomainIs      = $null
                    ExceptIfSentTo         = @('user1@contoso.com')
                    ExceptIfSentToMemberOf = $null
                })
            }
        }

        It 'Warns at Medium severity naming the rule, the policy type and the shadowed recipient' {
            $results = @(& $checkFile $METContext)
            $contra = $results | Where-Object Name -eq 'Preset Policy Coverage - Condition Contradictions'
            $contra | Should -Not -BeNullOrEmpty
            $contra.Result   | Should -Be 'Warning'
            $contra.Severity | Should -Be 'Medium'
            $contra.AffectedObject | Should -Be '1 rule(s) with include/exception conflicts'
            $contra.Finding | Should -Match "Safe Attachments rule 'SA - Finance' \(Priority 3\)"
            $contra.Finding | Should -Match 'user1@contoso\.com'
            $contra.Finding | Should -Match 'included via directly listed in SentTo; exception via directly listed in ExceptIfSentTo'
        }

        It 'Suppresses the clean Pass result' {
            $results = @(& $checkFile $METContext)
            ($results | Where-Object Result -eq 'Pass') | Should -BeNullOrEmpty
        }
    }

    Context 'The mailbox list cannot be retrieved' {
        BeforeEach {
            Mock Get-EXOMailbox { throw 'Insufficient access rights to perform the operation.' }
        }

        It 'Fails and carries the exception text in the Error field, not the Finding' {
            $results = @(& $checkFile $METContext)
            $results.Count | Should -Be 1
            $results[0].Result   | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'High'
            $results[0].AffectedObject | Should -Be 'All Mailboxes'
            $results[0].Finding | Should -Match 'Unable to retrieve mailbox list'
            $results[0].Error   | Should -Match 'Insufficient access rights'
            $results[0].Finding | Should -Not -Match 'Insufficient access rights'
        }
    }

    Context 'The tenant has no mailboxes' {
        BeforeEach {
            Mock Get-EXOMailbox { @() }
        }

        It 'Returns NotApplicable rather than a vacuous Pass' {
            $results = @(& $checkFile $METContext)
            $results.Count | Should -Be 1
            $results[0].Result   | Should -Be 'NotApplicable'
            $results[0].Severity | Should -Be 'High'
            $results[0].AffectedObject | Should -Be 'All Mailboxes'
            $results[0].Finding | Should -Match 'No mailboxes found'
        }
    }

    Context 'A preset policy rule collection cannot be retrieved' {
        BeforeEach {
            Mock Get-EXOMailbox { New-METTestMailboxes -Count 10 }
            Mock Get-EOPProtectionPolicyRule { throw 'EOP preset rules unavailable' }
            Mock Get-ATPProtectionPolicyRule { @(New-METTestPresetRule -Tier Strict -RecipientDomainIs 'contoso.com') }
        }

        It 'Fails against the coverage data rather than reporting a gap it cannot see' {
            $results = @(& $checkFile $METContext)
            $results.Count | Should -Be 1
            $results[0].Result   | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'High'
            $results[0].AffectedObject | Should -Be 'Policy Coverage Data'
            $results[0].Finding | Should -Match 'required policy or recipient data could not be retrieved'
            $results[0].Error   | Should -Match 'Unable to retrieve EOP preset policy rules'
            $results[0].Error   | Should -Match 'EOP preset rules unavailable'
        }

        It 'Does not cache an incomplete coverage matrix for later checks' {
            $null = & $checkFile $METContext
            $METContext.ContainsKey('CoverageMatrix') | Should -BeFalse
        }
    }

    Context 'A contradiction-analysis rule collection cannot be retrieved' {
        BeforeEach {
            Mock Get-EXOMailbox { New-METTestMailboxes -Count 10 }
            Mock Get-EOPProtectionPolicyRule { @(New-METTestPresetRule -Tier Strict -RecipientDomainIs 'contoso.com') }
            Mock Get-ATPProtectionPolicyRule { @(New-METTestPresetRule -Tier Strict -RecipientDomainIs 'contoso.com') }
            Mock Get-SafeAttachmentRule { throw 'Safe Attachment rules unavailable' }
        }

        It 'Fails against the contradiction data and names the failing rule collection in Error' {
            $results = @(& $checkFile $METContext)
            $results.Count | Should -Be 1
            $results[0].Result   | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'High'
            $results[0].AffectedObject | Should -Be 'Policy Contradiction Data'
            $results[0].Finding | Should -Match 'one or more rule collections could not be retrieved'
            $results[0].Error   | Should -Match 'Unable to retrieve Safe Attachments rules for contradiction analysis'
            $results[0].Error   | Should -Match 'Safe Attachment rules unavailable'
        }

        It 'Does not cache a coverage matrix whose contradiction analysis never ran' {
            $null = & $checkFile $METContext
            $METContext.ContainsKey('CoverageMatrix') | Should -BeFalse
        }
    }

    Context 'A group scope in a rule cannot be expanded during contradiction analysis' {
        BeforeEach {
            Mock Get-EXOMailbox { New-METTestMailboxes -Count 10 }
            Mock Get-EOPProtectionPolicyRule { @(New-METTestPresetRule -Tier Strict -RecipientDomainIs 'contoso.com') }
            Mock Get-ATPProtectionPolicyRule { @(New-METTestPresetRule -Tier Strict -RecipientDomainIs 'contoso.com') }
            Mock Get-DistributionGroupMember { throw 'group not found' }
            Mock Get-UnifiedGroupLinks       { throw 'not a Microsoft 365 Group' }
            Mock Get-SafeAttachmentRule {
                @([PSCustomObject]@{
                    Name                   = 'SA - Finance'
                    State                  = 'Enabled'
                    Priority               = 3
                    SentTo                 = @('user1@contoso.com')
                    SentToMemberOf         = $null
                    RecipientDomainIs      = $null
                    ExceptIfSentTo         = $null
                    ExceptIfSentToMemberOf = @('finance@contoso.com')
                })
            }
        }

        It 'Fails against the recipient data and names the group it could not expand' {
            $results = @(& $checkFile $METContext)
            $results.Count | Should -Be 1
            $results[0].Result   | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'High'
            $results[0].AffectedObject | Should -Be 'Policy Recipient Data'
            $results[0].Finding | Should -Match 'one or more group scopes could not be expanded'
            $results[0].Error   | Should -Match "Unable to expand group 'finance@contoso\.com'"
        }

        It 'Does not cache a coverage matrix built on unexpanded group scopes' {
            $null = & $checkFile $METContext
            $METContext.ContainsKey('CoverageMatrix') | Should -BeFalse
        }
    }

    Context 'A mailbox object omits PrimarySmtpAddress' {
        BeforeEach {
            Mock Get-EXOMailbox {
                @(
                    [PSCustomObject]@{ PrimarySmtpAddress = 'user1@contoso.com'; RecipientTypeDetails = 'UserMailbox' }
                    [PSCustomObject]@{ RecipientTypeDetails = 'UserMailbox' }
                )
            }
            Mock Get-EOPProtectionPolicyRule { @(New-METTestPresetRule -Tier Strict -RecipientDomainIs 'contoso.com') }
            Mock Get-ATPProtectionPolicyRule { @(New-METTestPresetRule -Tier Strict -RecipientDomainIs 'contoso.com') }
        }

        It 'Assesses only the mailboxes whose address was actually returned' {
            $results = @(& $checkFile $METContext)
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Pass'
            $results[0].AffectedObject | Should -Be 'Tenant (1 mailboxes)'
        }
    }

    Context 'The coverage matrix was pre-populated by an earlier check' {
        BeforeEach {
            Mock Get-EXOMailbox { throw 'Get-EXOMailbox must not be called when the context already holds the mailbox list' }
            Mock Get-EOPProtectionPolicyRule { @(New-METTestPresetRule -Tier Strict -RecipientDomainIs 'contoso.com') }
            Mock Get-ATPProtectionPolicyRule { @(New-METTestPresetRule -Tier Strict -RecipientDomainIs 'contoso.com') }
        }

        It 'Reuses the cached mailbox list instead of re-querying Exchange' {
            $METContext.AllMailboxes = @('user1@contoso.com', 'user2@contoso.com')
            $results = @(& $checkFile $METContext)
            $results[0].Result | Should -Be 'Pass'
            $results[0].AffectedObject | Should -Be 'Tenant (2 mailboxes)'
            Should -Invoke Get-EXOMailbox -Times 0
        }
    }
}
