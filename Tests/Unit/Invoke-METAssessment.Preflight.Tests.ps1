BeforeAll {
    $script:ModuleRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
    Import-Module (Join-Path $script:ModuleRoot 'MET.psd1') -Force -ErrorAction Stop
    $script:Module = Get-Module -Name 'MET'

    & $script:Module { Set-Item -Path 'function:script:Get-ConnectionInformation' -Value { } }
}

Describe 'Invoke-METAssessment connection preflight' {
    # With no session, the run leaked one raw exception as a warning, then took 95
    # seconds to produce 51 results reading Pass 0, Fail 0, Warning 4, Error 45 and a
    # posture of 11/Critical - an artifact a consultant could plausibly forward to a
    # customer.
    It 'throws rather than producing a report of 51 errors' {
        Mock -ModuleName 'MET' -CommandName 'Get-ConnectionInformation' -MockWith { }

        { Invoke-METAssessment -CheckId 'MET-MDO001' } |
            Should -Throw -ExpectedMessage '*Connect-METSession*'
    }

    It 'names an error id callers can catch by' {
        Mock -ModuleName 'MET' -CommandName 'Get-ConnectionInformation' -MockWith { }

        $caught = $null
        try { Invoke-METAssessment -CheckId 'MET-MDO001' } catch { $caught = $_ }

        $caught.FullyQualifiedErrorId | Should -BeLike 'METNotConnected*'
        $caught.CategoryInfo.Category  | Should -Be 'ConnectionError'
    }

    It 'does not throw when a session is connected' {
        Mock -ModuleName 'MET' -CommandName 'Get-ConnectionInformation' -MockWith {
            [PSCustomObject]@{ State = 'Connected'; Organization = 'contoso.onmicrosoft.com' }
        }
        Mock -ModuleName 'MET' -CommandName 'Get-AcceptedDomain' -MockWith { @() }

        { Invoke-METAssessment -CheckId 'MET-XXX999' -WarningAction SilentlyContinue } | Should -Not -Throw
    }

    It 'does not run any check before the guard fires' {
        Mock -ModuleName 'MET' -CommandName 'Get-ConnectionInformation' -MockWith { }
        Mock -ModuleName 'MET' -CommandName 'Get-AcceptedDomain' -MockWith { @() }

        try { Invoke-METAssessment } catch { }

        Should -Invoke -ModuleName 'MET' -CommandName 'Get-AcceptedDomain' -Times 0
    }
}

Describe 'Invoke-METAssessment check selection' {
    BeforeEach {
        Mock -ModuleName 'MET' -CommandName 'Get-ConnectionInformation' -MockWith {
            [PSCustomObject]@{ State = 'Connected'; Organization = 'contoso.onmicrosoft.com' }
        }
        Mock -ModuleName 'MET' -CommandName 'Get-AcceptedDomain' -MockWith { @() }
    }

    # All three of these silently ran zero checks, and @() | Get-METReport then
    # reported Posture Score: 0 / 100 [Critical] - a typo scored as catastrophic.
    It 'warns when a CheckId matches no check script' {
        $warnings = @()
        Invoke-METAssessment -CheckId 'MET-XXX999' -WarningVariable warnings -WarningAction SilentlyContinue | Out-Null

        ($warnings -join ' ') | Should -Match 'MET-XXX999'
        ($warnings -join ' ') | Should -Match 'Get-METCheck'
    }

    It 'warns when a CheckId is missing the MET- prefix' {
        $warnings = @()
        Invoke-METAssessment -CheckId 'EXO010' -WarningVariable warnings -WarningAction SilentlyContinue | Out-Null

        ($warnings -join ' ') | Should -Match 'EXO010'
    }

    It 'warns when an ExcludeCheckId matches no check script' {
        $warnings = @()
        Invoke-METAssessment -CheckId 'MET-MDO001' -ExcludeCheckId 'MET-XXX999' `
            -WarningVariable warnings -WarningAction SilentlyContinue | Out-Null

        ($warnings -join ' ') | Should -Match 'MET-XXX999'
    }

    It 'warns when the selection resolves to zero checks' {
        $warnings = @()
        Invoke-METAssessment -CheckId 'MET-EXO010' -ExcludeCheckId 'MET-EXO010' `
            -WarningVariable warnings -WarningAction SilentlyContinue | Out-Null

        ($warnings -join ' ') | Should -Match 'No checks'
    }

    It 'does not warn when every id matches' {
        $warnings = @()
        Invoke-METAssessment -CheckId 'MET-EXO010' -WarningVariable warnings -WarningAction SilentlyContinue | Out-Null

        ($warnings -join ' ') | Should -Not -Match 'matched no check'
    }
}
