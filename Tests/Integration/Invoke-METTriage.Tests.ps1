BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' '..' 'MET.psd1') -Force -ErrorAction Stop

    $script:METModule = Get-Module MET
    $script:CheckRoot = Join-Path $PSScriptRoot '..' '..' 'Checks'

    # Every service cmdlet a check (or a Private helper a check calls) reaches for.
    # Stubs must be created in the MODULE's session state, not the test file's:
    # Invoke-METTriage dot-sources check scripts inside a scriptblock bound to the
    # module, so name resolution walks module scope then global scope and never
    # reaches Pester's script scope. Stubs defined here as plain `function Get-X {}`
    # were therefore invisible to every check, and the whole run failed on
    # 'The term Get-AcceptedDomain is not recognized' while the suite reported green.
    # With the stubs in module scope, `Mock -ModuleName MET` reaches the checks.
    $script:TenantCmdlets = @(
        'Get-AcceptedDomain'
        'Get-AdminAuditLogConfig'
        'Get-AntiPhishPolicy'
        'Get-AntiPhishRule'
        'Get-ArcConfig'
        'Get-AtpPolicyForO365'
        'Get-ATPProtectionPolicyRule'
        'Get-CsExternalAccessPolicy'
        'Get-CsOnlineUser'
        'Get-CsTeamsAppPermissionPolicy'
        'Get-CsTeamsCallingPolicy'
        'Get-CsTeamsChannelsPolicy'
        'Get-CsTeamsClientConfiguration'
        'Get-CsTeamsExternalAccessConfiguration'
        'Get-CsTeamsGuestCallingConfiguration'
        'Get-CsTeamsGuestMessagingConfiguration'
        'Get-CsTeamsMeetingPolicy'
        'Get-CsTeamsMessagingPolicy'
        'Get-CsTenantFederationConfiguration'
        'Get-DistributionGroupMember'
        'Get-DkimSigningConfig'
        'Get-EmailTenantSettings'
        'Get-EOPProtectionPolicyRule'
        'Get-EXOCasMailbox'
        'Get-EXOMailbox'
        'Get-ExoPhishSimOverrideRule'
        'Get-ExoSecOpsOverrideRule'
        'Get-ExternalInOutlook'
        'Get-HostedConnectionFilterPolicy'
        'Get-HostedContentFilterPolicy'
        'Get-HostedContentFilterRule'
        'Get-HostedOutboundSpamFilterPolicy'
        'Get-HostedOutboundSpamFilterRule'
        'Get-InboundConnector'
        'Get-Mailbox'
        'Get-MalwareFilterPolicy'
        'Get-MalwareFilterRule'
        'Get-MgGroup'
        'Get-MgGroupTransitiveMember'
        'Get-MgPolicyAuthorizationPolicy'
        'Get-MgPolicyCrossTenantAccessPolicyDefault'
        'Get-OrganizationConfig'
        'Get-QuarantinePolicy'
        'Get-RemoteDomain'
        'Get-ReportSubmissionPolicy'
        'Get-ReportSubmissionRule'
        'Get-SafeAttachmentPolicy'
        'Get-SafeAttachmentRule'
        'Get-SafeLinksPolicy'
        'Get-SafeLinksRule'
        'Get-SharingPolicy'
        'Get-TeamsProtectionPolicy'
        'Get-TeamsProtectionPolicyRule'
        'Get-TenantAllowBlockListItems'
        'Get-TenantAllowBlockListSpoofItems'
        'Get-TransportConfig'
        'Get-TransportRule'
        'Get-UnifiedGroupLinks'
        'Get-User'
    )

    & $script:METModule {
        param([string[]] $Names)
        foreach ($name in $Names) {
            Set-Item -Path "function:script:$name" -Value { }
        }
    } $script:TenantCmdlets

    function Get-METCheckFile {
        param([string] $Category)
        $path = if ($Category) { Join-Path $script:CheckRoot $Category } else { $script:CheckRoot }
        @(Get-ChildItem -Path $path -Recurse -Filter 'MET-*.ps1')
    }
}

Describe 'Invoke-METTriage' {

    Context 'Mock reachability' {

        It 'Routes module-scoped mocks into the dot-sourced check scripts' {
            Mock -ModuleName MET Get-AcceptedDomain {
                @([PSCustomObject]@{ DomainName = 'contoso.com'; Default = $true; DomainType = 'Authoritative' })
            }
            Mock -ModuleName MET Get-AtpPolicyForO365 {
                [PSCustomObject]@{ EnableSafeDocs = $true; AllowSafeDocsOpen = $false }
            }

            $results = @(Invoke-METTriage -CheckId 'MET-MDO012')

            $results.Count             | Should -Be 1
            $results[0].Result         | Should -Be 'Pass'
            $results[0].Finding        | Should -Match 'Safe Documents is enabled'
            $results[0].Error          | Should -BeNullOrEmpty
            Should -Invoke -ModuleName MET Get-AtpPolicyForO365 -Exactly 1
        }
    }

    Context '-ListChecks dry-run' {

        It 'Returns check descriptors without executing checks' {
            Mock -ModuleName MET Get-AcceptedDomain { @() }

            $list = Invoke-METTriage -ListChecks
            $list | Should -Not -BeNullOrEmpty
            $list | ForEach-Object { $_ | Should -BeOfType [PSCustomObject] }
            Should -Invoke -ModuleName MET Get-AcceptedDomain -Exactly 0
        }

        It 'Every descriptor has CheckId, Category, and Script fields' {
            $list = Invoke-METTriage -ListChecks
            $list | Should -Not -BeNullOrEmpty
            $list | ForEach-Object {
                $_.PSObject.Properties.Name | Should -Contain 'CheckId'
                $_.PSObject.Properties.Name | Should -Contain 'Category'
                $_.PSObject.Properties.Name | Should -Contain 'Script'
            }
        }

        It 'CheckIds match the expected MET-XXX000 pattern' {
            $list = Invoke-METTriage -ListChecks
            $list | Should -Not -BeNullOrEmpty
            $list | ForEach-Object {
                $_.CheckId | Should -Match '^MET-(MDO|EXO|Teams)\d{3}$'
            }
        }

        It 'Respects -Category filter' {
            $mdoList = Invoke-METTriage -ListChecks -Category MDO
            $mdoList | Should -Not -BeNullOrEmpty
            $mdoList.Count | Should -Be (Get-METCheckFile -Category 'MDO').Count
            $mdoList | ForEach-Object { $_.Category | Should -Be 'MDO' }
        }

        It 'Respects -ExcludeCheckId filter' {
            $all      = Invoke-METTriage -ListChecks
            $filtered = Invoke-METTriage -ListChecks -ExcludeCheckId 'MET-MDO001'
            $filtered | Should -Not -BeNullOrEmpty
            $filtered | ForEach-Object { $_.CheckId | Should -Not -Be 'MET-MDO001' }
            $filtered.Count | Should -Be ($all.Count - 1)
        }

        It 'Lists exactly the check scripts present on disk' {
            # Derived from disk rather than a hardcoded total, so adding a check
            # cannot leave a stale literal silently asserting the old inventory.
            # The floor keeps the comparison from passing vacuously if the
            # discovery glob or the Checks tree itself is broken; 51 is the
            # inventory at the time of writing and is only ever raised.
            $onDisk = Get-METCheckFile
            $onDisk.Count | Should -BeGreaterOrEqual 51

            $list = Invoke-METTriage -ListChecks
            $list.Count | Should -Be $onDisk.Count
            @($list.Script | Sort-Object) | Should -Be @($onDisk.Name | Sort-Object)
        }
    }

    Context 'Shared $METContext' {

        BeforeEach {
            Mock -ModuleName MET Get-AcceptedDomain {
                @(
                    [PSCustomObject]@{ DomainName = 'contoso.com';   Default = $true;  DomainType = 'Authoritative' }
                    [PSCustomObject]@{ DomainName = 'fabrikam.com'; Default = $false; DomainType = 'Authoritative' }
                )
            }
        }

        It 'Pre-fetches accepted domains once and hands the same list to every check' {
            Mock -ModuleName MET Resolve-METDnsName {
                if ($Name -like '_dmarc.*') {
                    [PSCustomObject]@{ Name = $Name; Type = 'TXT'; Strings = @('v=DMARC1; p=reject; rua=mailto:dmarc@contoso.com') }
                }
                else {
                    [PSCustomObject]@{ Name = $Name; Type = 'TXT'; Strings = @('v=spf1 -all') }
                }
            }

            $results = @(Invoke-METTriage -CheckId 'MET-EXO001', 'MET-EXO003' -Detailed)

            # One Get-AcceptedDomain call for two checks that both consume the domain
            # list: the pre-fetch is shared, not repeated per check.
            Should -Invoke -ModuleName MET Get-AcceptedDomain -Exactly 1

            $dmarc = @($results | Where-Object CheckId -eq 'MET-EXO001')
            $spf   = @($results | Where-Object CheckId -eq 'MET-EXO003')

            @($dmarc.AffectedObject | Sort-Object) | Should -Be @('contoso.com', 'fabrikam.com')
            @($spf.AffectedObject   | Sort-Object) | Should -Be @('contoso.com', 'fabrikam.com')
            @($dmarc.Result | Sort-Object -Unique) | Should -Be @('Pass')
            @($spf.Result   | Sort-Object -Unique) | Should -Be @('Pass')
        }

        It 'Carries a mailbox list cached by one check forward to the next' {
            Mock -ModuleName MET Get-EXOMailbox {
                @([PSCustomObject]@{ PrimarySmtpAddress = 'alice@contoso.com'; RecipientTypeDetails = 'UserMailbox' })
            }

            $results = @(Invoke-METTriage -CheckId 'MET-MDO006', 'MET-MDO009' -Detailed)

            # Both checks resolve effective coverage over the tenant mailbox list.
            # The first stores it on $METContext; the second must reuse it, so the
            # underlying enumeration happens once for the whole run.
            Should -Invoke -ModuleName MET Get-EXOMailbox -Exactly 1

            @($results | Where-Object CheckId -eq 'MET-MDO006') | Should -Not -BeNullOrEmpty
            @($results | Where-Object CheckId -eq 'MET-MDO009') | Should -Not -BeNullOrEmpty
            @($results | Where-Object Finding -eq 'Check script failed to execute') | Should -BeNullOrEmpty
        }

        It 'Stamps the tenant name taken from the default accepted domain onto every result' {
            Mock -ModuleName MET Get-AtpPolicyForO365 {
                [PSCustomObject]@{ EnableSafeDocs = $true; AllowSafeDocsOpen = $false }
            }

            $results = @(Invoke-METTriage -CheckId 'MET-MDO012')

            $results[0].Metadata                 | Should -Not -BeNullOrEmpty
            $results[0].Metadata['METRunTenant'] | Should -Be 'contoso.com'
        }
    }

    Context 'A check that throws' {

        BeforeEach {
            Mock -ModuleName MET Get-AcceptedDomain {
                @([PSCustomObject]@{ DomainName = 'contoso.com'; Default = $true; DomainType = 'Authoritative' })
            }
            Mock -ModuleName MET Get-EXOMailbox {
                @([PSCustomObject]@{ PrimarySmtpAddress = 'alice@contoso.com'; RecipientTypeDetails = 'UserMailbox' })
            }
            Mock -ModuleName MET Get-AtpPolicyForO365 {
                [PSCustomObject]@{ EnableSafeDocs = $true; AllowSafeDocsOpen = $false }
            }
            Mock -ModuleName MET Get-OrganizationConfig {
                [PSCustomObject]@{ RejectDirectSend = $false }
            }
            # MET-MDO009 calls Resolve-METEffectivePolicy outside its own try/catch,
            # so this is a genuine terminating error escaping a check script.
            Mock -ModuleName MET Resolve-METEffectivePolicy { throw 'Deliberate check failure' }
        }

        It 'Converts the terminating error into a scored Fail result' {
            $results = @(Invoke-METTriage -CheckId 'MET-MDO009', 'MET-MDO012', 'MET-EXO010' -Detailed)

            $crashed = @($results | Where-Object CheckId -eq 'MET-MDO009')
            $crashed.Count             | Should -Be 1
            $crashed[0].Result         | Should -Be 'Fail'
            $crashed[0].Severity       | Should -Be 'High'
            # Must be 0 and not $null: Get-METReport only scores non-null Scores,
            # so a null here would drop every crashed check out of the posture index.
            $crashed[0].Score          | Should -Be 0
            $crashed[0].Score          | Should -Not -BeNullOrEmpty
            $crashed[0].Finding        | Should -Be 'Check script failed to execute'
            $crashed[0].Category       | Should -Be 'MDO'
            $crashed[0].AffectedObject | Should -Be 'N/A'
            $crashed[0].Error          | Should -Match 'Deliberate check failure'
        }

        It 'Leaves the neighbouring checks returning their real verdicts' {
            $results = @(Invoke-METTriage -CheckId 'MET-MDO009', 'MET-MDO012', 'MET-EXO010' -Detailed)

            @($results.CheckId | Sort-Object -Unique) |
                Should -Be @('MET-EXO010', 'MET-MDO009', 'MET-MDO012')

            $safeDocs = @($results | Where-Object CheckId -eq 'MET-MDO012')
            $safeDocs.Count      | Should -Be 1
            $safeDocs[0].Result  | Should -Be 'Pass'
            $safeDocs[0].Finding | Should -Match 'Safe Documents is enabled'
            $safeDocs[0].Error   | Should -BeNullOrEmpty

            $directSend = @($results | Where-Object CheckId -eq 'MET-EXO010')
            $directSend.Count      | Should -Be 1
            $directSend[0].Result  | Should -Be 'Fail'
            $directSend[0].Finding | Should -Match 'Direct Send is not blocked'
            $directSend[0].Finding | Should -Not -Be 'Check script failed to execute'
            $directSend[0].Error   | Should -BeNullOrEmpty
        }

        It 'Still stamps run provenance on the synthetic failure result' {
            $results = @(Invoke-METTriage -CheckId 'MET-MDO009' -Detailed)

            $results[0].Finding                  | Should -Be 'Check script failed to execute'
            $results[0].Metadata                 | Should -Not -BeNullOrEmpty
            $results[0].Metadata['METRunTenant'] | Should -Be 'contoso.com'
        }
    }

    Context '-Category filter' {

        It 'Returns one result per MDO check and nothing else with -Category MDO' {
            $results = @(Invoke-METTriage -Category MDO)
            $results | Should -Not -BeNullOrEmpty
            $results.Count | Should -Be (Get-METCheckFile -Category 'MDO').Count
            $results | ForEach-Object { $_.Category | Should -Be 'MDO' }
        }

        It 'Returns one result per EXO check and nothing else with -Category EXO' {
            $results = @(Invoke-METTriage -Category EXO)
            $results | Should -Not -BeNullOrEmpty
            $results.Count | Should -Be (Get-METCheckFile -Category 'EXO').Count
            $results | ForEach-Object { $_.Category | Should -Be 'EXO' }
        }

        It 'Returns one result per Teams check and nothing else with -Category Teams' {
            $results = @(Invoke-METTriage -Category Teams)
            $results | Should -Not -BeNullOrEmpty
            $results.Count | Should -Be (Get-METCheckFile -Category 'Teams').Count
            $results | ForEach-Object { $_.Category | Should -Be 'Teams' }
        }
    }

    Context '-CheckId filter' {

        It 'Returns only results for MET-MDO001 when specified' {
            $results = @(Invoke-METTriage -CheckId 'MET-MDO001')
            $results | Should -Not -BeNullOrEmpty
            $results | ForEach-Object { $_.CheckId | Should -Be 'MET-MDO001' }
        }
    }

    Context '-ExcludeCheckId filter' {

        It 'Excludes specified check from MDO results' {
            $all      = @(Invoke-METTriage -Category MDO)
            $excluded = @(Invoke-METTriage -Category MDO -ExcludeCheckId 'MET-MDO001')
            $excluded | Should -Not -BeNullOrEmpty
            $excluded | ForEach-Object { $_.CheckId | Should -Not -Be 'MET-MDO001' }
            $excluded.Count | Should -Be ($all.Count - 1)
        }
    }

    Context '-PassThru streaming' {

        BeforeEach {
            Mock -ModuleName MET Get-AcceptedDomain {
                @([PSCustomObject]@{ DomainName = 'contoso.com'; Default = $true; DomainType = 'Authoritative' })
            }
            # Two healthy domains: the default mode must collapse them into one
            # summary, -PassThru must stream both untouched.
            Mock -ModuleName MET Get-DkimSigningConfig {
                @('contoso.com', 'fabrikam.com') | ForEach-Object {
                    [PSCustomObject]@{
                        Domain                    = $_
                        Enabled                   = $true
                        Status                    = 'Valid'
                        Selector1KeySize          = 2048
                        Selector2KeySize          = 2048
                        SelectorBeforeRotateOnDate = 'selector1'
                        RotateOnDate              = $null
                    }
                }
            }
        }

        It 'Streams PSCustomObject results to the pipeline as checks complete' {
            $streamed = [System.Collections.Generic.List[PSCustomObject]]::new()
            Invoke-METTriage -CheckId 'MET-EXO002' -PassThru | ForEach-Object {
                $streamed.Add($_)
                $_ | Should -BeOfType [PSCustomObject]
            }
            $streamed.Count | Should -Be 2
        }

        It 'Streams the pre-aggregation objects the default mode collapses' {
            $streamed = @(Invoke-METTriage -CheckId 'MET-EXO002' -PassThru)
            $batch    = @(Invoke-METTriage -CheckId 'MET-EXO002')

            @($streamed.AffectedObject | Sort-Object) | Should -Be @('contoso.com', 'fabrikam.com')
            @($streamed.Result | Sort-Object -Unique) | Should -Be @('Pass')
            $streamed | ForEach-Object { $_.Finding | Should -Match '2048-bit key' }

            $batch.Count               | Should -Be 1
            $batch[0].AffectedObject   | Should -Be 'All 2 domains'
            $batch[0].Result           | Should -Be 'Pass'
            $batch[0].Finding          | Should -Match 'contoso\.com'
            $batch[0].Finding          | Should -Match 'fabrikam\.com'
        }

        It 'Streams exactly what -Detailed collects, object for object' {
            $collected = @(Invoke-METTriage -CheckId 'MET-EXO002' -Detailed)
            $streamed  = @(Invoke-METTriage -CheckId 'MET-EXO002' -PassThru)

            $streamed.Count | Should -Be $collected.Count
            for ($i = 0; $i -lt $collected.Count; $i++) {
                $streamed[$i].CheckId        | Should -Be $collected[$i].CheckId
                $streamed[$i].AffectedObject | Should -Be $collected[$i].AffectedObject
                $streamed[$i].Result         | Should -Be $collected[$i].Result
                $streamed[$i].Finding        | Should -Be $collected[$i].Finding
            }
        }
    }

    Context 'Output shape' {

        It 'Every result object has all required check result fields' {
            Mock -ModuleName MET Get-AcceptedDomain {
                @([PSCustomObject]@{ DomainName = 'contoso.com'; Default = $true; DomainType = 'Authoritative' })
            }
            Mock -ModuleName MET Get-AtpPolicyForO365 {
                [PSCustomObject]@{ EnableSafeDocs = $true; AllowSafeDocsOpen = $false }
            }

            $results = @(Invoke-METTriage -CheckId 'MET-MDO012')
            $results | Should -Not -BeNullOrEmpty
            $results[0].Result | Should -Be 'Pass'
            $results | ForEach-Object {
                $props = $_.PSObject.Properties.Name
                foreach ($field in @('CheckId','Category','Name','Result','Severity',
                                     'Score','AffectedObject','Finding','Recommendation',
                                     'ReferenceUrl','Timestamp','Error','Metadata')) {
                    $props | Should -Contain $field
                }
            }
        }
    }

    Context 'A check that produces no output' {

        It 'Emits a NotApplicable placeholder rather than vanishing from the run' {
            Mock -ModuleName MET Get-AntiPhishPolicy { @() }
            Mock -ModuleName MET Get-AntiPhishRule   { @() }

            $results = @(Invoke-METTriage -CheckId 'MET-MDO004' -Detailed)

            $results.Count       | Should -Be 1
            $results[0].CheckId  | Should -Be 'MET-MDO004'
            $results[0].Category | Should -Be 'MDO'
            $results[0].Result   | Should -Be 'NotApplicable'
            $results[0].Severity | Should -Be 'Informational'
            $results[0].Finding  | Should -Match 'produced no result'
        }
    }

    Context 'Full run' {

        It 'Returns exactly one aggregated result per check on disk without throwing' {
            $results = $null
            { $script:fullRun = @(Invoke-METTriage) } | Should -Not -Throw
            $results = $script:fullRun

            $onDisk = Get-METCheckFile
            $results.Count | Should -Be $onDisk.Count
            @($results.CheckId | Sort-Object -Unique).Count | Should -Be $onDisk.Count
            @($results | Where-Object { -not $_.CheckId }) | Should -BeNullOrEmpty
        }
    }
}
