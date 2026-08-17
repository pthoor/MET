BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Expand-METGroupMembership.ps1"
    . "$root/Private/Get-METAssessableMailboxes.ps1"
    . "$root/Public/Invoke-METTriage.ps1"

    function Get-AcceptedDomain           { [CmdletBinding()] param() }
    function Get-EXOMailbox               { [CmdletBinding()] param([string]$ResultSize,[string]$PropertySets) }
    function Get-EOPProtectionPolicyRule  { [CmdletBinding()] param([string]$Identity) }
    function Get-ATPProtectionPolicyRule  { [CmdletBinding()] param([string]$Identity) }
    function Get-HostedContentFilterRule  { [CmdletBinding()] param() }
    function Get-SafeLinksRule            { [CmdletBinding()] param() }
    function Get-SafeAttachmentRule       { [CmdletBinding()] param() }
    function Get-AntiPhishRule            { [CmdletBinding()] param() }
    function Get-MgGroup                  { [CmdletBinding()] param([string]$Filter,[int]$Top) }
    function Get-MgGroupTransitiveMember  { [CmdletBinding()] param([string]$GroupId,[switch]$All) }
    function Get-DistributionGroupMember  { [CmdletBinding()] param([string]$Identity,[string]$ResultSize) }
    function Get-UnifiedGroupLinks        { [CmdletBinding()] param([string]$Identity,[string]$LinkType,[string]$ResultSize) }
}

Describe 'Invoke-METTriage default aggregation' {
    BeforeEach {
        Mock Get-AcceptedDomain           { @() }
        Mock Get-MgGroup                  { throw 'Graph not available' }
        Mock Get-MgGroupTransitiveMember  { throw 'Graph not available' }
        Mock Get-EOPProtectionPolicyRule  { @() }
        Mock Get-ATPProtectionPolicyRule  { @() }
        Mock Get-HostedContentFilterRule  { @() }
        Mock Get-SafeAttachmentRule       { @() }
        Mock Get-AntiPhishRule            { @() }
        Mock Get-EXOMailbox {
            @('alice@contoso.com') | ForEach-Object { [PSCustomObject]@{ PrimarySmtpAddress = $_ } }
        }

        # Two healthy groups - both produce Info results from MET-MDO014.
        Mock Get-SafeLinksRule {
            @(
                [PSCustomObject]@{ Name = 'Sales Rule'; State = 'Enabled'; SentTo = $null; SentToMemberOf = @('Sales DL'); ExceptIfSentToMemberOf = $null }
                [PSCustomObject]@{ Name = 'Legal Rule'; State = 'Enabled'; SentTo = $null; SentToMemberOf = @('Legal DL'); ExceptIfSentToMemberOf = $null }
            )
        }
        Mock Get-DistributionGroupMember {
            @([PSCustomObject]@{ RecipientType = 'MailUser'; PrimarySmtpAddress = 'alice@contoso.com' })
        }
    }

    Context 'A check emits multiple Info results and no Fail/Warning' {
        It 'Collapses them into one summary instead of dropping all but the first' {
            $results = @(Invoke-METTriage -CheckId 'MET-MDO014' -WarningAction SilentlyContinue)

            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Info'
            $results[0].AffectedObject | Should -Be 'All 2 groups'
            $results[0].Finding | Should -Match 'Sales DL'
            $results[0].Finding | Should -Match 'Legal DL'
        }

        It 'Still returns every individual result with -Detailed' {
            $results = @(Invoke-METTriage -CheckId 'MET-MDO014' -Detailed -WarningAction SilentlyContinue)

            $results.Count | Should -Be 2
            @($results | ForEach-Object AffectedObject) | Should -Contain 'Sales DL'
            @($results | ForEach-Object AffectedObject) | Should -Contain 'Legal DL'
        }
    }
}
