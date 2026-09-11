BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
    . (Join-Path $script:Root 'Private' 'New-METCheckResult.ps1')
    . (Join-Path $script:Root 'Public'  'Import-METReport.ps1')

    # The round-trip test pipes into Get-METReport, which needs most of Private/ loaded.
    Import-Module (Join-Path $script:Root 'MET.psd1') -Force -ErrorAction Stop

    $script:SavedReport = Join-Path $TestDrive 'saved.json'
    @'
{
  "tenant": "contoso.onmicrosoft.com",
  "runTimestamp": "2026-06-01T14:32:00Z",
  "METVersion": "0.11.1",
  "authentication": {
    "authMode": "ServicePrincipal",
    "deviceCodeUsed": false,
    "tenantIdentity": "contoso.onmicrosoft.com",
    "servicesConnected": ["ExchangeOnline", "Teams"]
  },
  "postureScore": 74,
  "scoreBand": "Fair",
  "categoryScores": { "MDO": 81, "EXO": 68, "Teams": 72 },
  "summary": { "Pass": 1, "Fail": 1, "Warning": 0, "NotApplicable": 0, "Error": 0 },
  "checks": [
    {
      "checkId": "MET-MDO001", "category": "MDO", "name": "Safe Links Policy",
      "result": "Fail", "severity": "High", "score": 0,
      "affectedObject": "Default Safe Links Policy",
      "finding": "Safe Links is disabled for email",
      "recommendation": "Enable Safe Links",
      "referenceUrl": "https://aka.ms/safelinks",
      "timestamp": "2026-06-01T14:32:05Z", "error": null, "metadata": null
    },
    {
      "checkId": "MET-EXO001", "category": "EXO", "name": "DMARC",
      "result": "Pass", "severity": "High", "score": 100,
      "affectedObject": "contoso.com", "finding": "DMARC at reject",
      "recommendation": "", "referenceUrl": "",
      "timestamp": "2026-06-01T14:32:06Z", "error": null, "metadata": null
    }
  ]
}
'@ | Set-Content -LiteralPath $script:SavedReport -Encoding utf8
}

Describe 'Import-METReport' {

    It 'Returns one object per saved check' {
        @(Import-METReport -Path $script:SavedReport).Count | Should -Be 2
    }

    It 'Restores PascalCase property names rather than relying on case-insensitive access' {
        # The accident C-20 names: ConvertFrom-Json yields 'checkId', and $_.CheckId
        # resolving is a PowerShell courtesy, not a contract. ConvertTo-Json on the way
        # back out would emit the camelCase names a second time.
        #
        # Pester's `Should -Contain`/`-Not -Contain` calls straight through to PowerShell's
        # `-contains` operator, which is case-insensitive for strings by default - so
        # `Should -Not -Contain 'checkId'` would report a failure even for a correctly
        # PascalCase-only object, since 'checkId' -contains-matches 'CheckId'. Using that
        # assertion here would be committing the exact case-insensitivity accident this test
        # exists to catch, just inside the test itself. `-ccontains` (case-sensitive) is used
        # instead to keep the check meaningful.
        $imported = @(Import-METReport -Path $script:SavedReport)[0]
        $imported.PSObject.Properties.Name | Should -Contain 'CheckId'
        ($imported.PSObject.Properties.Name -ccontains 'checkId') | Should -BeFalse
    }

    It 'Restores the type stamp so the table view applies' {
        @(Import-METReport -Path $script:SavedReport)[0].PSObject.TypeNames |
            Should -Contain 'MET.CheckResult'
    }

    It 'Restores Timestamp as a UTC datetime, not a string' {
        $imported = @(Import-METReport -Path $script:SavedReport)[0]
        $imported.Timestamp | Should -BeOfType [datetime]
        $imported.Timestamp.Kind | Should -Be ([System.DateTimeKind]::Utc)
    }

    It 'Carries the original tenant on every result, so a re-render is labelled correctly' {
        # Without this the re-rendered report takes its label from whatever tenant the
        # current session happens to be connected to - one customer's configuration under
        # another customer's name, the exposure A-1 and A-2 were about.
        foreach ($result in (Import-METReport -Path $script:SavedReport)) {
            $result.Metadata['METRunTenant'] | Should -Be 'contoso.onmicrosoft.com'
        }
    }

    It 'Carries the original authentication block' {
        $imported = @(Import-METReport -Path $script:SavedReport)[0]
        $imported.Metadata['METRunAuthentication'].authMode | Should -Be 'ServicePrincipal'
        @($imported.Metadata['METRunAuthentication'].servicesConnected) | Should -Contain 'Teams'
    }

    It 'Round-trips through Get-METReport with the original tenant on the page' {
        # Get-METReport nests its output under a timestamped subfolder rather than honouring
        # a literal -OutputPath file path (a known, pre-existing defect tracked separately -
        # not fixed here). Pass a folder and locate the generated file the same way
        # Get-METReport.Html.Tests.ps1 and ControlsMetadata.Tests.ps1 already do, rather than
        # assuming -OutputPath names the file directly.
        $folder = Join-Path $TestDrive 'rerendered'
        Import-METReport -Path $script:SavedReport | Get-METReport -Format HTML -OutputPath $folder -NoLaunch | Out-Null
        $generated = Get-ChildItem -Path $folder -Recurse -Filter '*.html' | Select-Object -First 1
        $generated | Should -Not -BeNullOrEmpty
        (Get-Content -LiteralPath $generated.FullName -Raw) | Should -BeLike '*contoso.onmicrosoft.com*'
    }

    It 'Throws a readable error on a file that is not a MET report' {
        $notAReport = Join-Path $TestDrive 'other.json'
        '{"hello":"world"}' | Set-Content -LiteralPath $notAReport -Encoding utf8
        { Import-METReport -Path $notAReport } | Should -Throw '*checks*'
    }

    It 'Throws a readable error on a file that is not JSON at all' {
        $notJson = Join-Path $TestDrive 'notjson.txt'
        'plain text' | Set-Content -LiteralPath $notJson -Encoding utf8
        { Import-METReport -Path $notJson } | Should -Throw
    }
}
