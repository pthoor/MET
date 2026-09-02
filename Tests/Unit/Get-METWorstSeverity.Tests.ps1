BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/Get-METWorstSeverity.ps1"
    . "$root/Private/Get-METSafeSeverity.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"
}

Describe 'Get-METCheckWeight' {
    # The entire posture score rests on these five numbers. Pin them.
    It 'Returns the documented weight for <Severity>' -ForEach @(
        @{ Severity = 'Critical';      Weight = 40 }
        @{ Severity = 'High';          Weight = 20 }
        @{ Severity = 'Medium';        Weight = 10 }
        @{ Severity = 'Low';           Weight = 5 }
        @{ Severity = 'Informational'; Weight = 0 }
    ) {
        Get-METCheckWeight -Severity $Severity | Should -Be $Weight
    }

    It 'Gives Informational zero weight, which removes it from the score entirely' {
        Get-METCheckWeight -Severity 'Informational' | Should -Be 0
    }
}

Describe 'Get-METWorstSeverity' {
    It 'Returns the highest-weighted severity in the set' {
        Get-METWorstSeverity -Severity @('Low', 'Critical', 'Medium') | Should -Be 'Critical'
    }

    # This is the aggregation bug that removed real findings from the posture score:
    # MET-EXO001 emits Informational for the tenant's .mail.onmicrosoft.com routing
    # domain before it reaches a customer-facing domain that fails. Inheriting the
    # first item's severity stamped the aggregate Informational, weight 0, which drops
    # it out of both the numerator and the denominator.
    It 'Does not let a leading Informational item mask a later High finding' {
        Get-METWorstSeverity -Severity @('Informational', 'High') | Should -Be 'High'
    }

    It 'Is order-independent' {
        Get-METWorstSeverity -Severity @('High', 'Informational') |
            Should -Be (Get-METWorstSeverity -Severity @('Informational', 'High'))
    }

    It 'Ignores null and empty entries rather than throwing' {
        Get-METWorstSeverity -Severity @($null, '', 'Medium') | Should -Be 'Medium'
    }

    It 'Ignores unrecognised entries' {
        Get-METWorstSeverity -Severity @('Catastrophic', 'Low') | Should -Be 'Low'
    }

    It 'Falls back to Informational for an empty set' {
        Get-METWorstSeverity -Severity @() | Should -Be 'Informational'
    }

    It 'Accepts pipeline input' {
        @('Low', 'Critical') | Get-METWorstSeverity | Should -Be 'Critical'
    }
}

Describe 'Get-METSafeSeverity' {
    It 'Passes a known severity through unchanged' {
        Get-METSafeSeverity -Severity 'Critical' | Should -Be 'Critical'
    }

    It 'Normalises null, empty and unknown severities to Informational' -ForEach @(
        @{ Input = $null }
        @{ Input = '' }
        @{ Input = '   ' }
        @{ Input = 'Catastrophic' }
    ) {
        Get-METSafeSeverity -Severity $Input | Should -Be 'Informational'
    }

    It 'Always returns a value Get-METCheckWeight accepts' {
        # Get-METCheckWeight has a ValidateSet; an unnormalised value throws inside the
        # scoring loop and no report is produced at all.
        foreach ($candidate in @($null, '', 'Nonsense', 'High')) {
            { Get-METCheckWeight -Severity (Get-METSafeSeverity -Severity $candidate) } | Should -Not -Throw
        }
    }
}
