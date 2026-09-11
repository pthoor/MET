BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
    . (Join-Path $script:Root 'Private' 'Get-METCheckMetadata.ps1')
    . (Join-Path $script:Root 'Public'  'Get-METCheck.ps1')
}

Describe 'Get-METCheck' {

    It 'Returns one entry per check script on disk' {
        $onDisk = @(Get-ChildItem -Path (Join-Path $script:Root 'Checks') -Recurse -Filter 'MET-*.ps1')
        @(Get-METCheck).Count | Should -Be $onDisk.Count
    }

    It 'Enumerates in the order Invoke-METAssessment runs checks' {
        # -ListChecks delegates here (Task 5) and the integration suite asserts the listed
        # order. Sorting differently would make the dry-run stop predicting the real run.
        $expected = @(Get-ChildItem -Path (Join-Path $script:Root 'Checks') -Recurse -Filter 'MET-*.ps1' |
            Sort-Object Name | ForEach-Object { ($_.BaseName -split '-')[0..1] -join '-' })
        @(Get-METCheck).CheckId | Should -Be $expected
    }

    It 'Filters by category' {
        $mdo = @(Get-METCheck -Category MDO)
        $mdo.Count | Should -BeGreaterThan 0
        @($mdo | Where-Object Category -ne 'MDO') | Should -BeNullOrEmpty
    }

    It 'Filters by check id, accepting several' {
        $picked = @(Get-METCheck -CheckId 'MET-EXO001', 'MET-MDO009')
        @($picked.CheckId) | Should -Be @('MET-EXO001', 'MET-MDO009')
    }

    It 'Returns nothing rather than throwing for an id that matches no check' {
        @(Get-METCheck -CheckId 'MET-NOPE999') | Should -BeNullOrEmpty
    }

    It 'Filters by severity, which means the worst the check can score' {
        $high = @(Get-METCheck -Severity High)
        $high.Count | Should -BeGreaterThan 0
        @($high | Where-Object Severity -ne 'High') | Should -BeNullOrEmpty
    }

    It 'Combines filters with AND' {
        $combined = @(Get-METCheck -Category EXO -Severity High)
        $combined.Count | Should -BeGreaterThan 0
        @($combined | Where-Object { $_.Category -ne 'EXO' -or $_.Severity -ne 'High' }) | Should -BeNullOrEmpty
    }

    It 'Runs with no Exchange Online module loaded and no session' {
        # The load-bearing claim of the whole design. Get-METCheck is what a user runs to
        # decide whether to connect at all; it must not need what it is describing.
        Get-Module ExchangeOnlineManagement | Remove-Module -Force -ErrorAction SilentlyContinue
        { Get-METCheck } | Should -Not -Throw
        @(Get-METCheck).Count | Should -BeGreaterThan 0
    }

    It 'Rejects a category outside the three that exist' {
        { Get-METCheck -Category 'Purview' } | Should -Throw
    }

    It 'Skips a check file that fails to parse, warns naming it, and still returns the rest' {
        # Reproduces the failure a real unparseable file under Checks/ used to cause: Get-METCheckMetadata
        # throws on a parse error, and an uncaught throw here previously killed Get-METReport's whole
        # HTML generation (via its unguarded CONTROLS_META call to Get-METCheck), not just the listing.
        $badPath = Join-Path $script:Root 'Checks' 'MDO' 'MET-MDO999-Bad.ps1'
        Set-Content -LiteralPath $badPath -Value 'function {' -Encoding utf8
        try {
            $expectedCount = @(Get-ChildItem -Path (Join-Path $script:Root 'Checks') -Recurse -Filter 'MET-*.ps1').Count - 1

            $warnings = $null
            $result = @(Get-METCheck -WarningVariable warnings -WarningAction SilentlyContinue)

            $result.Count      | Should -Be $expectedCount
            $result.CheckId    | Should -Not -Contain 'MET-MDO999'
            ($warnings.Message -join ' ') | Should -Match ([regex]::Escape($badPath))
        } finally {
            Remove-Item -LiteralPath $badPath -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe '-ListChecks delegation' {

    BeforeAll {
        . (Join-Path $script:Root 'Public' 'Invoke-METAssessment.ps1')
    }

    It 'Returns the same objects Get-METCheck returns' {
        # C-16: the old -ListChecks emitted CheckId/Category/Script only, so the documented
        # dry run could not answer "what does this check do?" - the question it exists for.
        $listed = @(Invoke-METAssessment -ListChecks)
        $direct = @(Get-METCheck)
        $listed.CheckId | Should -Be $direct.CheckId
        $listed[0].PSObject.Properties.Name | Should -Contain 'Description'
        $listed[0].PSObject.Properties.Name | Should -Contain 'Severity'
        $listed[0].Description | Should -Not -BeNullOrEmpty
    }

    It 'Still honours -Category when listing' {
        @(Invoke-METAssessment -ListChecks -Category Teams | Where-Object Category -ne 'Teams') |
            Should -BeNullOrEmpty
    }

    It 'Lists nothing when the filters resolve to no checks' {
        # An empty array is falsy in PowerShell, so a naive delegation lists everything
        # here - the dry run would promise 51 checks for a run that executes none.
        @(Invoke-METAssessment -ListChecks -CheckId 'MET-NOPE999' -WarningAction SilentlyContinue) |
            Should -BeNullOrEmpty
    }

    It 'Completes -CheckId from the checks on disk' {
        # cursorColumn is the literal string length (verified: 'Invoke-METAssessment
        # -CheckId MET-EXO01'.Length -eq 39), not length + 2 as the brief's snippet had it -
        # TabExpansion2 throws PSArgumentException on an out-of-range cursorIndex rather than
        # just returning nothing.
        $inputScript = 'Invoke-METAssessment -CheckId MET-EXO01'
        $completions = TabExpansion2 -inputScript $inputScript -cursorColumn $inputScript.Length
        @($completions.CompletionMatches.CompletionText) | Should -Contain 'MET-EXO010'
    }

    It 'Completes -ExcludeCheckId the same way' {
        $inputScript = 'Invoke-METAssessment -ExcludeCheckId MET-MDO01'
        $completions = TabExpansion2 -inputScript $inputScript -cursorColumn $inputScript.Length
        @($completions.CompletionMatches.CompletionText) | Should -Contain 'MET-MDO010'
    }
}
