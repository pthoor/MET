BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' '..' 'MET.psd1') -Force -ErrorAction Stop

    # Stub all external EXO cmdlets at session scope so check scripts can run
    # without a live tenant. Returning $null causes checks to emit Fail/Warning
    # results via their own error handling — that is intentional here.
    function Get-SafeLinksPolicy                  { [CmdletBinding()] param([string]$Identity) }
    function Get-SafeAttachmentPolicy             { [CmdletBinding()] param([string]$Identity) }
    function Get-AntiPhishPolicy                  { [CmdletBinding()] param([string]$Identity) }
    function Get-AntiPhishRule                    { [CmdletBinding()] param([string]$Identity) }
    function Get-MalwareFilterPolicy              { [CmdletBinding()] param([string]$Identity) }
    function Get-HostedContentFilterPolicy        { [CmdletBinding()] param([string]$Identity) }
    function Get-HostedContentFilterRule          { [CmdletBinding()] param([string]$Identity) }
    function Get-HostedOutboundSpamFilterPolicy   { [CmdletBinding()] param([string]$Identity) }
    function Get-EOPProtectionPolicyRule          { [CmdletBinding()] param([string]$Identity) }
    function Get-EXOMailbox                       { [CmdletBinding()] param([string]$Identity) }
    function Get-DistributionGroupMember          { [CmdletBinding()] param([string]$Identity) }
    function Get-User                             { [CmdletBinding()] param([string]$Filter) }
    function Get-Tag                              { [CmdletBinding()] param([string]$Identity) }
    function Get-ProtectionAlert                  { [CmdletBinding()] param([string]$Identity) }
    function Get-AcceptedDomain                   { [CmdletBinding()] param() }
    function Get-DkimSigningConfig                { [CmdletBinding()] param([string]$Identity) }
    function Get-QuarantinePolicy                 { [CmdletBinding()] param([string]$Identity) }
    function Get-TenantAllowBlockListItems        { [CmdletBinding()] param([string]$ListType) }
    function Get-ReportSubmissionPolicy           { [CmdletBinding()] param() }
    function Get-TransportRule                    { [CmdletBinding()] param() }
    function Get-AtpPolicyForO365                 { [CmdletBinding()] param([string]$Identity) }
    function Get-CsTenantFederationConfiguration  { [CmdletBinding()] param() }
    function Get-CsTeamsMeetingPolicy             { [CmdletBinding()] param() }
    function Get-EmailTenantSettings              { [CmdletBinding()] param() }
    function Get-TeamsProtectionPolicy            { [CmdletBinding()] param() }
    function Get-CsTeamsMessagingPolicy           { [CmdletBinding()] param() }
}

Describe 'Invoke-METTriage' {

    Context '-ListChecks dry-run' {

        It 'Returns check descriptors without executing checks' {
            $list = Invoke-METTriage -ListChecks
            $list | Should -Not -BeNullOrEmpty
            $list | ForEach-Object { $_ | Should -BeOfType [PSCustomObject] }
        }

        It 'Every descriptor has CheckId, Category, and Script fields' {
            $list = Invoke-METTriage -ListChecks
            $list | ForEach-Object {
                $_.PSObject.Properties.Name | Should -Contain 'CheckId'
                $_.PSObject.Properties.Name | Should -Contain 'Category'
                $_.PSObject.Properties.Name | Should -Contain 'Script'
            }
        }

        It 'CheckIds match the expected MET-XXX000 pattern' {
            $list = Invoke-METTriage -ListChecks
            $list | ForEach-Object {
                $_.CheckId | Should -Match '^MET-(MDO|EXO|Teams)\d{3}$'
            }
        }

        It 'Respects -Category filter' {
            $mdoList = Invoke-METTriage -ListChecks -Category MDO
            $mdoList | Should -Not -BeNullOrEmpty
            $mdoList | ForEach-Object { $_.Category | Should -Be 'MDO' }
        }

        It 'Respects -ExcludeCheckId filter' {
            $all      = Invoke-METTriage -ListChecks
            $filtered = Invoke-METTriage -ListChecks -ExcludeCheckId 'MET-MDO001'
            $filtered | ForEach-Object { $_.CheckId | Should -Not -Be 'MET-MDO001' }
            $filtered.Count | Should -Be ($all.Count - 1)
        }

        It 'Covers all 26 checks across MDO, EXO, and Teams' {
            $list = Invoke-METTriage -ListChecks
            $list.Count | Should -Be 26
        }
    }

    Context '-Category filter' {

        It 'Returns only MDO results with -Category MDO' {
            $results = Invoke-METTriage -Category MDO
            $results | Where-Object { $_ } | ForEach-Object {
                $_.Category | Should -Be 'MDO'
            }
        }

        It 'Returns only EXO results with -Category EXO' {
            $results = Invoke-METTriage -Category EXO
            $results | Where-Object { $_ } | ForEach-Object {
                $_.Category | Should -Be 'EXO'
            }
        }

        It 'Returns only Teams results with -Category Teams' {
            $results = Invoke-METTriage -Category Teams
            $results | Where-Object { $_ } | ForEach-Object {
                $_.Category | Should -Be 'Teams'
            }
        }
    }

    Context '-CheckId filter' {

        It 'Returns only results for MET-MDO001 when specified' {
            $results = Invoke-METTriage -CheckId 'MET-MDO001'
            $results | Should -Not -BeNullOrEmpty
            $results | ForEach-Object { $_.CheckId | Should -Be 'MET-MDO001' }
        }
    }

    Context '-ExcludeCheckId filter' {

        It 'Excludes specified check from MDO results' {
            $all      = Invoke-METTriage -Category MDO
            $excluded = Invoke-METTriage -Category MDO -ExcludeCheckId 'MET-MDO001'
            $excluded | ForEach-Object { $_.CheckId | Should -Not -Be 'MET-MDO001' }
            $excluded.Count | Should -BeLessThan $all.Count
        }
    }

    Context '-PassThru streaming' {

        It 'Streams PSCustomObject results to the pipeline as checks complete' {
            $streamed = [System.Collections.Generic.List[PSCustomObject]]::new()
            Invoke-METTriage -Category MDO -PassThru | ForEach-Object {
                $streamed.Add($_)
                $_ | Should -BeOfType [PSCustomObject]
            }
            $streamed | Should -Not -BeNullOrEmpty
        }

        It 'Produces the same results as the default (collect-then-return) mode' {
            $batch    = Invoke-METTriage -Category MDO
            $streamed = Invoke-METTriage -Category MDO -PassThru | ForEach-Object { $_ }
            $streamed.Count | Should -Be $batch.Count
        }
    }

    Context 'Output shape' {

        It 'Every result object has all required check result fields' {
            $results = Invoke-METTriage -CheckId 'MET-MDO001'
            $results | Should -Not -BeNullOrEmpty
            $results | ForEach-Object {
                $props = $_.PSObject.Properties.Name
                foreach ($field in @('CheckId','Category','Name','Result','Severity',
                                     'Score','AffectedObject','Finding','Recommendation',
                                     'ReferenceUrl','Timestamp','Error')) {
                    $props | Should -Contain $field
                }
            }
        }
    }

    Context 'Error resilience' {

        It 'Does not throw when all checks fail to connect' {
            { Invoke-METTriage -Category MDO } | Should -Not -Throw
        }

        It 'Does not throw when running all checks' {
            { Invoke-METTriage } | Should -Not -Throw
        }
    }
}
