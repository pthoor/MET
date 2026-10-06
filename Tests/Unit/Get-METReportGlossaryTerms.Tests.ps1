# Pins the term-extraction rules documented inline in Get-METReportGlossaryTerms.ps1 against
# the real Checks/ tree (there is no path parameter to redirect it - by design, it always
# reflects the shipped checks), plus the shape guarantees (sorted, unique, degrades to an
# empty array) that Get-METReport's HTML generation depends on.
BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
    . (Join-Path $script:Root 'Private' 'Get-METReportGlossaryTerms.ps1')
}

Describe 'Get-METReportGlossaryTerms' {

    BeforeAll {
        $script:Terms = @(Get-METReportGlossaryTerms)
    }

    It 'returns a non-empty list drawn from the real Checks tree' {
        $script:Terms.Count | Should -BeGreaterThan 0
    }

    It 'returns unique, sorted values' {
        ($script:Terms | Sort-Object) | Should -Be $script:Terms
        ($script:Terms | Select-Object -Unique).Count | Should -Be $script:Terms.Count
    }

    It 'includes multi-segment PascalCase parameter/property names actually referenced by checks' {
        $script:Terms | Should -Contain 'RejectDirectSend'
        $script:Terms | Should -Contain 'SmtpClientAuthenticationDisabled'
    }

    It 'includes cmdlet names actually invoked by checks' {
        $script:Terms | Should -Contain 'Get-EXOMailbox'
    }

    It 'includes quoted built-in policy name string constants' {
        $script:Terms | Should -Contain 'AdminOnlyAccessPolicy'
    }

    It 'excludes PowerShell common parameters even though they are PascalCase' {
        $script:Terms | Should -Not -Contain 'ErrorAction'
        $script:Terms | Should -Not -Contain 'WarningAction'
    }

    It 'excludes single-segment PascalCase words that read as ordinary prose' {
        $script:Terms | Should -Not -Contain 'Identity'
    }

    It 'excludes short category/protocol acronyms below the length floor' {
        $script:Terms | Should -Not -Contain 'EXO'
        $script:Terms | Should -Not -Contain 'MDO'
        $script:Terms | Should -Not -Contain 'SPF'
    }

    It 'contains no term longer than the stated ceiling' {
        ($script:Terms | Where-Object { $_.Length -gt 80 }) | Should -BeNullOrEmpty
    }

    It 'contains no term shorter than the stated floor' {
        ($script:Terms | Where-Object { $_.Length -lt 6 }) | Should -BeNullOrEmpty
    }
}

Describe 'Get-METReportGlossaryTerms degraded conditions' {

    It 'returns an empty array rather than throwing when the Checks folder is missing' {
        Mock Test-Path { $false }

        $result = @(Get-METReportGlossaryTerms)

        $result | Should -BeNullOrEmpty
    }

    It 'skips a check file that fails to parse rather than throwing' {
        $badFile = Join-Path $TestDrive 'MET-FAKE999-Broken.ps1'
        Set-Content -LiteralPath $badFile -Value 'function ( this is not valid PowerShell {'

        Mock Get-ChildItem { [System.IO.FileInfo]::new($badFile) } -ParameterFilter { $Filter -eq 'MET-*.ps1' }

        { Get-METReportGlossaryTerms } | Should -Not -Throw
        @(Get-METReportGlossaryTerms) | Should -BeNullOrEmpty
    }
}
