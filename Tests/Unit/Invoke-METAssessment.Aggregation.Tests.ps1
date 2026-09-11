BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METEndUserQuarantinePermission.ps1"
    . "$root/Private/Get-METWorstSeverity.ps1"
    . "$root/Private/Test-METIsBuiltInQuarantinePolicyName.ps1"
    . "$root/Private/Expand-METGroupMembership.ps1"
    . "$root/Private/Get-METAssessableMailboxes.ps1"
    . "$root/Public/Invoke-METAssessment.ps1"

    function Get-AcceptedDomain           { [CmdletBinding()] param() }
    function Get-ConnectionInformation    { [CmdletBinding()] param() }
    function Get-EXOMailbox               { [CmdletBinding()] param([string]$ResultSize,[string]$PropertySets,[string[]]$Properties,[string]$Filter) }
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
    function Get-DkimSigningConfig        { [CmdletBinding()] param([string]$Identity) }
    function Get-QuarantinePolicy         { [CmdletBinding()] param([string]$Identity,[string]$QuarantinePolicyType) }
    function Get-AtpPolicyForO365         { [CmdletBinding()] param([string]$Identity) }
    function Get-SafeAttachmentPolicy     { [CmdletBinding()] param([string]$Identity) }
    function Get-EmailTenantSettings      { [CmdletBinding()] param() }
    function Get-User                     { [CmdletBinding()] param([switch]$IsVIP,[string]$ResultSize) }
}

Describe 'Invoke-METAssessment default aggregation' {
    BeforeEach {
        Mock Get-ConnectionInformation     { [PSCustomObject]@{ State = 'Connected' } }
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
            $results = @(Invoke-METAssessment -CheckId 'MET-MDO014' -WarningAction SilentlyContinue)

            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Info'
            $results[0].AffectedObject | Should -Be 'All 2 groups'
            $results[0].Finding | Should -Match 'Sales DL'
            $results[0].Finding | Should -Match 'Legal DL'
        }

        It 'Still returns every individual result with -Detailed' {
            $results = @(Invoke-METAssessment -CheckId 'MET-MDO014' -Detailed -WarningAction SilentlyContinue)

            $results.Count | Should -Be 2
            @($results | ForEach-Object AffectedObject) | Should -Contain 'Sales DL'
            @($results | ForEach-Object AffectedObject) | Should -Contain 'Legal DL'
        }
    }

    Context 'tenant provenance survives aggregation' {
        BeforeEach {
            Mock Get-AcceptedDomain {
                @([PSCustomObject]@{ DomainName = 'contoso.com'; Default = $true; DomainType = 'Authoritative' })
            }
        }

        It 'Stamps METRunTenant on the all-info summary aggregate (both groups healthy)' {
            $results = @(Invoke-METAssessment -CheckId 'MET-MDO014' -WarningAction SilentlyContinue)

            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Info'
            $results[0].Metadata | Should -Not -BeNullOrEmpty
            $results[0].Metadata['METRunTenant'] | Should -Be 'contoso.com'
        }

        It 'Stamps METRunTenant on the fail/warn aggregate (one group empty)' {
            Mock Get-DistributionGroupMember {
                param([string]$Identity, [string]$ResultSize)
                if ($Identity -eq 'Legal DL') { return @() }
                @([PSCustomObject]@{ RecipientType = 'MailUser'; PrimarySmtpAddress = 'alice@contoso.com' })
            }

            $results = @(Invoke-METAssessment -CheckId 'MET-MDO014' -WarningAction SilentlyContinue)

            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Fail'
            $results[0].Metadata | Should -Not -BeNullOrEmpty
            $results[0].Metadata['METRunTenant'] | Should -Be 'contoso.com'
        }
    }
}

Describe 'Invoke-METAssessment mixed-result aggregation' {
    BeforeEach {
        Mock Get-ConnectionInformation { [PSCustomObject]@{ State = 'Connected' } }
        Mock Get-AcceptedDomain { @() }
    }

    Context 'A check emits one Fail among many Pass results' {
        BeforeEach {
            # Nine healthy domains and one with DKIM switched off, all under MET-EXO002.
            Mock Get-DkimSigningConfig {
                @(1..4 | ForEach-Object { "ok$_.contoso.com" }) +
                @('broken.contoso.com') +
                @(5..9 | ForEach-Object { "ok$_.contoso.com" }) |
                    ForEach-Object {
                        [PSCustomObject]@{
                            Domain                     = $_
                            Enabled                    = ($_ -ne 'broken.contoso.com')
                            Status                     = 'Valid'
                            Selector1KeySize           = 2048
                            Selector2KeySize           = 2048
                            SelectorBeforeRotateOnDate = 'selector1'
                            RotateOnDate               = $null
                        }
                    }
            }
        }

        It 'Reports the aggregate as a Fail counting only the failing domain' {
            $results = @(Invoke-METAssessment -CheckId 'MET-EXO002' -WarningAction SilentlyContinue)

            $results.Count           | Should -Be 1
            $results[0].Result       | Should -Be 'Fail'
            $results[0].Score        | Should -Be 0
            $results[0].Severity     | Should -Be 'High'
            $results[0].AffectedObject | Should -Be '1 of 10 domains'
        }

        It 'Keeps only the failing domain in the aggregated Finding' {
            $results = @(Invoke-METAssessment -CheckId 'MET-EXO002' -WarningAction SilentlyContinue)

            $results[0].Finding | Should -Match 'broken\.contoso\.com'
            $results[0].Finding | Should -Not -Match 'ok1\.contoso\.com'
            $results[0].Error   | Should -BeNullOrEmpty
        }

        It 'Still returns all ten per-domain results with -Detailed' {
            $results = @(Invoke-METAssessment -CheckId 'MET-EXO002' -Detailed -WarningAction SilentlyContinue)

            $results.Count | Should -Be 10
            @($results | Where-Object Result -eq 'Fail').Count | Should -Be 1
            @($results | Where-Object Result -eq 'Pass').Count | Should -Be 9
        }
    }

    Context 'A check emits Warning results and no Fail' {
        BeforeEach {
            # Custom quarantine policies only - the four built-ins are filtered out by
            # the check itself, so all three of these reach the aggregation.
            Mock Get-QuarantinePolicy {
                @(
                    [PSCustomObject]@{ Name = 'CustomNoNotify1'; ESNEnabled = $false; EndUserQuarantinePermissions = "[PermissionToRelease: False`nPermissionToDelete: True`nPermissionToPreview: True]" }
                    [PSCustomObject]@{ Name = 'CustomHealthy';   ESNEnabled = $true;  EndUserQuarantinePermissions = "[PermissionToRelease: False`nPermissionToDelete: True`nPermissionToPreview: True]" }
                    [PSCustomObject]@{ Name = 'CustomNoNotify2'; ESNEnabled = $false; EndUserQuarantinePermissions = "[PermissionToRelease: False`nPermissionToRequestRelease: True`nPermissionToPreview: True]" }
                )
            }
        }

        It 'Reports the aggregate as a Warning, not a Fail' {
            $results = @(Invoke-METAssessment -CheckId 'MET-EXO004' -WarningAction SilentlyContinue)

            $results.Count             | Should -Be 1
            $results[0].Result         | Should -Be 'Warning'
            $results[0].Score          | Should -Be 50
            $results[0].Severity       | Should -Be 'Medium'
            $results[0].AffectedObject | Should -Be '2 of 3 quarantine policies'
        }

        It 'Names the warned policies and leaves the healthy one out of the Finding' {
            $results = @(Invoke-METAssessment -CheckId 'MET-EXO004' -WarningAction SilentlyContinue)

            $results[0].Finding | Should -Match 'CustomNoNotify1'
            $results[0].Finding | Should -Match 'CustomNoNotify2'
            $results[0].Finding | Should -Not -Match 'CustomHealthy'
        }
    }

    Context 'A check emits a result carrying an Error but no Fail or Warning' {
        BeforeEach {
            # The global policy answers without EnableATPForSPOTeamsODB, which MET-MDO002
            # reports as NotApplicable with the absence recorded in ErrorMessage. The
            # Built-In policy passes, so the group has an error item and no Fail/Warning.
            Mock Get-AtpPolicyForO365 { [PSCustomObject]@{ EnableSafeDocs = $true } }
            Mock Get-SafeAttachmentRule { @() }
            Mock Get-SafeAttachmentPolicy {
                @([PSCustomObject]@{ Name = 'Built-In Protection Policy'; Enable = $true; Action = 'Block' })
            }
        }

        It 'Produces exactly the underlying mix the branch is meant to handle' {
            $results = @(Invoke-METAssessment -CheckId 'MET-MDO002' -Detailed -WarningAction SilentlyContinue)

            $results.Count | Should -Be 2
            @($results.Result | Sort-Object) | Should -Be @('NotApplicable', 'Pass')
            @($results | Where-Object { $_.Error }).Count | Should -Be 1
        }

        It 'Escalates the aggregate to Fail and carries the error text forward' {
            $results = @(Invoke-METAssessment -CheckId 'MET-MDO002' -WarningAction SilentlyContinue)

            $results.Count             | Should -Be 1
            $results[0].Result         | Should -Be 'Fail'
            $results[0].Severity       | Should -Be 'High'
            $results[0].AffectedObject | Should -Be '1 of 2 policies'
            $results[0].Error          | Should -Match 'did not return an EnableATPForSPOTeamsODB value'
            $results[0].Finding        | Should -Match 'Global Safe Attachments Settings'
            $results[0].Finding        | Should -Not -Match 'Built-In Protection Policy'
        }
    }

    Context 'A Warning item co-occurs with a higher-severity errored item under one CheckId' {
        BeforeEach {
            # MET-MDO010 emits two results: the protection toggle (High) and the tagging
            # sub-check (Medium). Here the toggle property is absent -> NotApplicable/High
            # carrying an Error, and no user is tagged -> Warning/Medium. The aggregate
            # must take the worst severity across BOTH, not just the warning.
            Mock Get-EmailTenantSettings { [PSCustomObject]@{ Identity = 'contoso' } }
            Mock Get-User { @() }
        }

        It 'Emits the two underlying results with the expected severities' {
            $results = @(Invoke-METAssessment -CheckId 'MET-MDO010' -Detailed -WarningAction SilentlyContinue)
            $results.Count | Should -Be 2
            ($results | Where-Object { $_.Result -eq 'NotApplicable' }).Severity | Should -Be 'High'
            ($results | Where-Object { $_.Result -eq 'Warning' }).Severity | Should -Be 'Medium'
        }

        It 'Scores the aggregate at the errored item severity (High), not the warning (Medium)' {
            $results = @(Invoke-METAssessment -CheckId 'MET-MDO010' -WarningAction SilentlyContinue)

            $results.Count       | Should -Be 1
            $results[0].Result   | Should -Be 'Warning'
            $results[0].Severity | Should -Be 'High'
            $results[0].Error    | Should -Match 'did not return an EnablePriorityAccountProtection value'
            $results[0].Finding  | Should -Match 'was not returned by Get-EmailTenantSettings'
            $results[0].Finding  | Should -Match 'No users have the Priority Account tag'
        }
    }
}

Describe 'Get-METAggregationNoun' {
    It 'Calls the email authentication checks domains' {
        Get-METAggregationNoun -CheckId 'MET-EXO001' | Should -Be 'domains'
        Get-METAggregationNoun -CheckId 'MET-EXO002' | Should -Be 'domains'
        Get-METAggregationNoun -CheckId 'MET-EXO003' | Should -Be 'domains'
    }

    It 'Calls the quarantine policy check quarantine policies' {
        Get-METAggregationNoun -CheckId 'MET-EXO004' | Should -Be 'quarantine policies'
    }

    It 'Falls back to policies for a check with no noun of its own' {
        Get-METAggregationNoun -CheckId 'MET-MDO001' | Should -Be 'policies'
        Get-METAggregationNoun -CheckId 'MET-EXO099' | Should -Be 'policies'
    }
}
