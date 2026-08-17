BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Expand-METGroupMembership.ps1"
    . "$root/Private/Get-METAssessableMailboxes.ps1"

    function Get-EXOMailbox              { [CmdletBinding()] param([string]$ResultSize,[string]$PropertySets) }
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

    $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'MDO' 'MET-MDO014-GroupReferenceAudit.ps1'
}

Describe 'MET-MDO014 Group Reference Audit' {
    BeforeEach {
        Mock Get-MgGroup                 { throw 'Graph not available' }
        Mock Get-MgGroupTransitiveMember { throw 'Graph not available' }
        Mock Get-EOPProtectionPolicyRule { @() }
        Mock Get-ATPProtectionPolicyRule { @() }
        Mock Get-HostedContentFilterRule { @() }
        Mock Get-SafeAttachmentRule      { @() }
        Mock Get-AntiPhishRule           { @() }
        $METContext = @{}
    }

    Context 'No mailboxes exist' {
        BeforeAll { Mock Get-EXOMailbox { @() } }

        It 'Returns NotApplicable' {
            Mock Get-SafeLinksRule { @() }
            $results = & $checkFile
            $results[0].Result | Should -Be 'NotApplicable'
            $results[0].CheckId | Should -Be 'MET-MDO014'
        }
    }

    Context 'No enabled rule references a group' {
        BeforeAll {
            Mock Get-EXOMailbox {
                @('alice@contoso.com') | ForEach-Object { [PSCustomObject]@{ PrimarySmtpAddress = $_ } }
            }
        }

        It 'Returns NotApplicable' {
            Mock Get-SafeLinksRule {
                @([PSCustomObject]@{ Name = 'Direct only'; State = 'Enabled'; SentTo = @('alice@contoso.com'); SentToMemberOf = $null; ExceptIfSentToMemberOf = $null })
            }
            $results = & $checkFile
            $results[0].Result | Should -Be 'NotApplicable'
        }
    }

    Context 'A referenced group has zero members' {
        BeforeAll {
            Mock Get-EXOMailbox {
                @('alice@contoso.com') | ForEach-Object { [PSCustomObject]@{ PrimarySmtpAddress = $_ } }
            }
            Mock Get-DistributionGroupMember { @() }
        }

        It 'Reports Fail for that group, naming the referencing rule' {
            Mock Get-SafeLinksRule {
                @([PSCustomObject]@{ Name = 'Empty Group Rule'; State = 'Enabled'; SentTo = $null; SentToMemberOf = @('Ghost Group'); ExceptIfSentToMemberOf = $null })
            }
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Fail'
            $results[0].AffectedObject | Should -Be 'Ghost Group'
            $results[0].Finding | Should -Match 'Empty Group Rule'
        }
    }

    Context 'A referenced group has members' {
        BeforeAll {
            Mock Get-EXOMailbox {
                @('alice@contoso.com') | ForEach-Object { [PSCustomObject]@{ PrimarySmtpAddress = $_ } }
            }
            Mock Get-DistributionGroupMember {
                @([PSCustomObject]@{ RecipientType = 'MailUser'; PrimarySmtpAddress = 'alice@contoso.com' })
            }
        }

        It 'Reports Info with the member count' {
            Mock Get-SafeLinksRule {
                @([PSCustomObject]@{ Name = 'Sales Rule'; State = 'Enabled'; SentTo = $null; SentToMemberOf = @('Sales DL'); ExceptIfSentToMemberOf = $null })
            }
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Info'
            $results[0].AffectedObject | Should -Be 'Sales DL'
            $results[0].Finding | Should -Match '1 member'
            $results[0].Finding | Should -Match 'Sales Rule'
        }
    }

    Context 'The same group is referenced by two different rules' {
        BeforeAll {
            Mock Get-EXOMailbox {
                @('alice@contoso.com') | ForEach-Object { [PSCustomObject]@{ PrimarySmtpAddress = $_ } }
            }
            Mock Get-DistributionGroupMember {
                @([PSCustomObject]@{ RecipientType = 'MailUser'; PrimarySmtpAddress = 'alice@contoso.com' })
            }
        }

        It 'Emits a single result naming both rules, not one result per rule' {
            Mock Get-SafeLinksRule {
                @([PSCustomObject]@{ Name = 'Rule A'; State = 'Enabled'; SentTo = $null; SentToMemberOf = @('Shared Group'); ExceptIfSentToMemberOf = $null })
            }
            Mock Get-AntiPhishRule {
                @([PSCustomObject]@{ Name = 'Rule B'; State = 'Enabled'; SentTo = $null; SentToMemberOf = @('Shared Group'); ExceptIfSentToMemberOf = $null })
            }
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Finding | Should -Match 'Rule A'
            $results[0].Finding | Should -Match 'Rule B'
        }
    }

    Context 'Rule retrieval fails' {
        BeforeAll {
            Mock Get-EXOMailbox {
                @('alice@contoso.com') | ForEach-Object { [PSCustomObject]@{ PrimarySmtpAddress = $_ } }
            }
        }

        It 'Returns Fail with the retrieval error captured' {
            Mock Get-SafeLinksRule { throw 'Access denied' }
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Error | Should -Match 'Access denied'
        }
    }
}
