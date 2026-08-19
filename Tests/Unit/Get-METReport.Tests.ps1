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

    It 'does not double-count results that carry both a Result and a populated Error field' {
        $output = Join-Path $TestDrive 'reports-error-summary'
        $results = @(
            [PSCustomObject]@{
                CheckId = 'MET-Teams009'; Category = 'Teams'; Name = 'Pass check'
                Result = 'Pass'; Severity = 'High'; Score = 100; AffectedObject = 'Tenant'
                Finding = 'ok'; Recommendation = ''; ReferenceUrl = ''
                Timestamp = [datetime]::UtcNow; Error = $null
            },
            [PSCustomObject]@{
                CheckId = 'MET-Teams010'; Category = 'Teams'; Name = 'Fail with retrieval error'
                Result = 'Fail'; Severity = 'Medium'; Score = 0; AffectedObject = 'Tenant'
                Finding = 'could not retrieve'; Recommendation = ''; ReferenceUrl = ''
                Timestamp = [datetime]::UtcNow; Error = 'Get-CsExternalAccessPolicy threw'
            },
            [PSCustomObject]@{
                CheckId = 'MET-Teams014'; Category = 'Teams'; Name = 'NotApplicable with error detail'
                Result = 'NotApplicable'; Severity = 'Medium'; Score = $null; AffectedObject = 'Tenant'
                Finding = 'Graph unavailable'; Recommendation = ''; ReferenceUrl = ''
                Timestamp = [datetime]::UtcNow; Error = 'Authentication needed. Please call Connect-MgGraph.'
            }
        )

        $results | Get-METReport -Format JSON -OutputPath $output -TenantName 'contoso.com'
        $folder = Get-ChildItem $output -Directory | Select-Object -First 1
        $json = Get-Content (Join-Path $folder.FullName 'MET-report.json') -Raw | ConvertFrom-Json

        $json.checks | Should -HaveCount 3
        $total = $json.summary.Pass + $json.summary.Fail + $json.summary.Warning + $json.summary.NotApplicable + $json.summary.Info + $json.summary.Error
        $total | Should -Be 3
        $json.summary.Pass | Should -Be 1
        $json.summary.Fail | Should -Be 0
        $json.summary.NotApplicable | Should -Be 0
        $json.summary.Error | Should -Be 2
    }

    It 'counts Info results in the summary and includes them in the console/JSON total' {
        $output = Join-Path $TestDrive 'reports-info-summary'
        $results = @(
            [PSCustomObject]@{
                CheckId = 'MET-EXO016'; Category = 'EXO'; Name = 'ARC Trusted Sealers Review'
                Result = 'Info'; Severity = 'Low'; Score = $null; AffectedObject = 'ARC Trusted Sealers'
                Finding = 'No ARC trusted sealers configured'; Recommendation = ''; ReferenceUrl = ''
                Timestamp = [datetime]::UtcNow; Error = $null
            },
            [PSCustomObject]@{
                CheckId = 'MET-EXO017'; Category = 'EXO'; Name = 'Quarantine Notification Cadence'
                Result = 'Info'; Severity = 'Informational'; Score = $null; AffectedObject = 'Global Quarantine Notification Settings'
                Finding = 'Sent every 4 hours'; Recommendation = ''; ReferenceUrl = ''
                Timestamp = [datetime]::UtcNow; Error = $null
            },
            [PSCustomObject]@{
                CheckId = 'MET-EXO001'; Category = 'EXO'; Name = 'DMARC'
                Result = 'Pass'; Severity = 'High'; Score = 100; AffectedObject = 'contoso.com'
                Finding = 'ok'; Recommendation = ''; ReferenceUrl = ''
                Timestamp = [datetime]::UtcNow; Error = $null
            }
        )

        $results | Get-METReport -Format JSON -OutputPath $output -TenantName 'contoso.com'
        $folder = Get-ChildItem $output -Directory | Select-Object -First 1
        $json = Get-Content (Join-Path $folder.FullName 'MET-report.json') -Raw | ConvertFrom-Json

        $json.checks | Should -HaveCount 3
        $json.summary.Info | Should -Be 2
        $json.summary.Pass | Should -Be 1
        $total = $json.summary.Pass + $json.summary.Fail + $json.summary.Warning + $json.summary.NotApplicable + $json.summary.Info + $json.summary.Error
        $total | Should -Be 3
    }
}
