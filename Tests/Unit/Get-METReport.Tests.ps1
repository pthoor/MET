BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' '..' 'MET.psd1') -Force -ErrorAction Stop
}

Describe 'Get-METReport structured metadata' {
    It 'preserves effective policy coverage metadata in JSON and HTML' {
        $output = Join-Path $TestDrive 'reports'
        $result = [PSCustomObject]@{
            CheckId = 'MET-MDO001'; Category = 'MDO'; Name = 'Safe Links Effective Coverage'
            Result = 'Pass'; Severity = 'High'; Score = 100; AffectedObject = 'Tenant (2 mailboxes)'
            Finding = 'All recipients meet the baseline.'; Recommendation = ''; ReferenceUrl = 'https://aka.ms/mdo-safelinks'
            Timestamp = [datetime]::UtcNow; Error = $null
            Metadata = @{ DetailType = 'EffectivePolicyCoverage'; ProtectionType = 'Safe Links'; TotalRecipients = 2; OrderingObservations = @(@{ Severity='Warning'; Message='Catch-all shadows a specialized policy' }); CoverageRecommendations=@('Add a compliant catch-all after specialized policies'); Policies = @(@{ PolicyName = 'Strict custom'; EffectiveRecipientCount = 2; OrderingObservations=@('Catch-all shadows a specialized policy') }) }
        }

        $result | Get-METReport -Format All -OutputPath $output -TenantName 'contoso.com'
        $folder = Get-ChildItem $output -Directory | Select-Object -First 1
        $json = Get-Content (Join-Path $folder.FullName 'MET-report.json') -Raw | ConvertFrom-Json
        $html = Get-Content (Join-Path $folder.FullName 'MET-report.html') -Raw

        $json.checks | Should -HaveCount 1
        $json.checks[0].metadata.totalRecipients | Should -Be 2
        $json.checks[0].metadata.policies[0].policyName | Should -Be 'Strict custom'
        $json.checks[0].metadata.orderingObservations[0].severity | Should -Be 'Warning'
        $html | Should -Match 'EffectivePolicyCoverage'
        $html | Should -Match 'ProtectionType.*Safe Links'
        $html | Should -Match 'coverage-table'
        $html | Should -Match '<th>Scope</th>'
        $html | Should -Match '<th>Effective recipients</th>'
        $html | Should -Match '<th>Configuration</th>'
        $html | Should -Match '<th>Current impact</th>'
        $html | Should -Match '<th>Ordering observations</th>'
        $html | Should -Match 'Catch-all shadows a specialized policy'
        $html | Should -Match 'Add a compliant catch-all after specialized policies'
        $html | Should -Not -Match ([string][char]0x2014)
    }
}
