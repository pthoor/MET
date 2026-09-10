BeforeAll {
    $root = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
    Import-Module (Join-Path $root 'MET.psd1') -Force -ErrorAction Stop

    $script:SchemaFile = Join-Path $root 'docs' 'schema' 'MET-report-schema.json'

    function New-METSchemaTestResult {
        param(
            [string] $CheckId,
            [string] $Category,
            [string] $Name,
            [string] $Result,
            [string] $Severity,
            $Score,
            $ErrorText = $null
        )
        [PSCustomObject]@{
            CheckId        = $CheckId
            Category       = $Category
            Name           = $Name
            Result         = $Result
            Severity       = $Severity
            Score          = $Score
            AffectedObject = 'Default Policy'
            Finding        = 'Observed configuration.'
            Recommendation = 'Remediate in the portal.'
            ReferenceUrl   = 'https://aka.ms/mdo-safelinks'
            Timestamp      = [datetime]::UtcNow
            Error          = $ErrorText
        }
    }

    function Get-METJsonReport {
        param([object[]] $Results)
        # -Format JSON with no -OutputPath returns the document on the pipeline; ConvertTo-Json
        # emits it as a single string, but joining keeps this immune to a future line-per-object
        # emission. An empty $Results pipes nothing, which is exactly the zero-result run.
        ($Results | Get-METReport -Format JSON -TenantName 'contoso.onmicrosoft.com') -join "`n"
    }

    function Remove-METPinnedSchemaViolation {
        param([string] $Json)
        $doc = $Json | ConvertFrom-Json -AsHashtable
        $doc | ConvertTo-Json -Depth 10
    }

    function Test-METReportAgainstSchema {
        param([string] $Json)
        Test-Json -Json $Json -SchemaFile $script:SchemaFile -ErrorAction Stop
    }

    $script:MixedResults = @(
        (New-METSchemaTestResult -CheckId 'MET-MDO001' -Category 'MDO'   -Name 'Safe Links Effective Coverage' -Result 'Pass'          -Severity 'High'          -Score 100),
        (New-METSchemaTestResult -CheckId 'MET-EXO001' -Category 'EXO'   -Name 'DMARC'                        -Result 'Fail'          -Severity 'Critical'      -Score 0),
        (New-METSchemaTestResult -CheckId 'MET-EXO022' -Category 'EXO'   -Name 'Calendar and Contact Sharing Policies' -Result 'Warning' -Severity 'Medium'    -Score 50),
        (New-METSchemaTestResult -CheckId 'MET-EXO016' -Category 'EXO'   -Name 'ARC Trusted Sealers Review'   -Result 'Info'          -Severity 'Informational' -Score $null),
        (New-METSchemaTestResult -CheckId 'MET-Teams012' -Category 'Teams' -Name 'Call Reporting'             -Result 'NotApplicable' -Severity 'Low'          -Score $null)
    )
    $script:ErrorResult = New-METSchemaTestResult -CheckId 'MET-Teams014' -Category 'Teams' `
        -Name 'Cross-Tenant Guest & External Collaboration Restrictions' -Result 'NotApplicable' `
        -Severity 'Medium' -Score $null -ErrorText 'Authentication needed. Please call Connect-MgGraph.'
}

Describe 'Get-METReport JSON output against docs/schema/MET-report-schema.json' {

    It 'Validates the schema file itself is loadable by Test-Json' {
        $minimal = @'
{"tenant":"contoso.onmicrosoft.com","runTimestamp":"2026-01-01T00:00:00Z","METVersion":"0.0.0",
 "postureScore":50,"categoryScores":{"MDO":100,"EXO":null,"Teams":null},
 "summary":{"Pass":1,"Fail":0,"Warning":0,"Info":0,"NotApplicable":0,"Error":0},"checks":[]}
'@
        Test-METReportAgainstSchema -Json $minimal | Should -BeTrue
        # And that it rejects - a validator that accepts everything would make this whole file
        # green for the wrong reason.
        { Test-METReportAgainstSchema -Json ($minimal -replace '"checks":\[\]', '"checks":{}') } |
            Should -Throw -ExpectedMessage '*should be "array" at ''/checks''*'
    }

    Context 'A mixed result set covering every Result value' {

        It 'Validates once the two pinned violations are removed' {
            $json = Get-METJsonReport -Results $script:MixedResults
            Test-METReportAgainstSchema -Json (Remove-METPinnedSchemaViolation -Json $json) | Should -BeTrue
        }

        It 'Emits checks as a JSON array' {
            $json = Get-METJsonReport -Results $script:MixedResults
            $json | Should -Match '"checks":\s*\['
        }

        It 'Reports every scored and unscored result' {
            $doc = Get-METJsonReport -Results $script:MixedResults | ConvertFrom-Json
            @($doc.checks).Count | Should -Be 5
            $doc.summary.Pass | Should -Be 1
            $doc.summary.Fail | Should -Be 1
        }
    }

    Context 'A single-result run' {

        # ConvertTo-Json has collapsed a one-element collection to a bare object before now,
        # which both broke the HTML report's client script and emitted checks as an object
        # rather than an array here. Asserted on the raw text, not on a deserialised value:
        # ConvertFrom-Json unwraps a one-element array either way, so only the text can tell
        # the two apart.
        It 'Emits checks as a JSON array, not a bare object' {
            $json = Get-METJsonReport -Results @($script:MixedResults[0])
            $json | Should -Match '"checks":\s*\['
            $json | Should -Not -Match '"checks":\s*\{'
        }

        It 'Validates once the two pinned violations are removed' {
            $json = Get-METJsonReport -Results @($script:MixedResults[0])
            Test-METReportAgainstSchema -Json (Remove-METPinnedSchemaViolation -Json $json) | Should -BeTrue
        }
    }

    Context 'A zero-result run' {

        It 'Emits checks as an empty JSON array, not null or an object' {
            $json = Get-METJsonReport -Results @()
            $json | Should -Match '"checks":\s*\[\s*\]'
        }

        It 'Validates once the pinned root violation is removed' {
            $json = Get-METJsonReport -Results @()
            Test-METReportAgainstSchema -Json (Remove-METPinnedSchemaViolation -Json $json) | Should -BeTrue
        }
    }

    Context 'A result carrying a populated Error' {

        It 'Validates once the two pinned violations are removed' {
            $json = Get-METJsonReport -Results @($script:ErrorResult)
            Test-METReportAgainstSchema -Json (Remove-METPinnedSchemaViolation -Json $json) | Should -BeTrue
        }

        It 'Emits the error as a string and counts it in its own summary bucket' {
            $doc = Get-METJsonReport -Results @($script:ErrorResult) | ConvertFrom-Json
            $doc.checks[0].error | Should -BeOfType [string]
            $doc.summary.Error | Should -Be 1
            $doc.summary.NotApplicable | Should -Be 0
        }
    }

    Context 'Properties the published schema now permits' {

        # /authentication (root) and /checks/<n>/metadata (per check) are both really emitted
        # on every run - authentication null when Get-METReport was not reached through
        # Connect-METSession, otherwise an object of authMode, deviceCodeUsed, tenantIdentity,
        # servicesConnected; metadata null unless the check attached structured detail. Both
        # used to be rejected by "additionalProperties": false on the root object and on
        # definitions/checkResult respectively, so every report MET produced failed the
        # contract it publishes. The schema now declares both properties instead.
        It 'Validates a full report against the published schema unmodified' {
            $json = Get-METJsonReport -Results $script:MixedResults
            $json | Should -Match '"authentication":'
            { Test-Json -Json $json -SchemaFile $script:SchemaFile -ErrorAction Stop } |
                Should -Not -Throw
        }

        It 'Validates a report carrying per-check metadata unmodified' {
            $json = Get-METJsonReport -Results $script:MixedResults
            $json | Should -Match '"metadata":'
            { Test-Json -Json $json -SchemaFile $script:SchemaFile -ErrorAction Stop } |
                Should -Not -Throw
        }

        It 'Emits a scoreBand alongside the numeric score' {
            $doc = Get-METJsonReport -Results $script:MixedResults | ConvertFrom-Json
            $doc.scoreBand | Should -BeIn @('Critical','Poor','Fair','Good','Excellent','None')
        }

        It 'Validates a zero-result run against the published schema unmodified' {
            # The root authentication property does not need a single check result to occur, so
            # even an empty run must ship a document that validates unmodified.
            { Test-METReportAgainstSchema -Json (Get-METJsonReport -Results @()) } |
                Should -Not -Throw
        }
    }
}
