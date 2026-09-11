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
}
