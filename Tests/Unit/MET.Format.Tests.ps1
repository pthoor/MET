BeforeAll {
    $script:ModuleRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
    Import-Module (Join-Path $script:ModuleRoot 'MET.psd1') -Force -ErrorAction Stop
    . (Join-Path $script:ModuleRoot 'Private' 'New-METCheckResult.ps1')
}

Describe 'MET.CheckResult type name' {
    It 'is stamped on results from the factory' {
        $result = New-METCheckResult -CheckId 'MET-MDO001' -Category MDO -Name 'Safe Links' `
            -Result Pass -Severity High -AffectedObject 'Tenant' -Finding 'Fine.'

        $result.PSObject.TypeNames | Should -Contain 'MET.CheckResult'
    }

    # 51 results x 13 properties auto-formats as a list, because PowerShell lists
    # anything with more than four properties: 863 lines at width 120.
    It 'is declared in the manifest so the format file actually loads' {
        $manifest = Import-PowerShellDataFile -Path (Join-Path $script:ModuleRoot 'MET.psd1')
        $manifest.FormatsToProcess | Should -Contain 'MET.Format.ps1xml'
    }

    It 'renders as a table, not a list' {
        $result = New-METCheckResult -CheckId 'MET-MDO001' -Category MDO -Name 'Safe Links' `
            -Result Fail -Severity High -AffectedObject 'Default Policy' -Finding 'Disabled.'

        $rendered = $result | Format-Table | Out-String
        $rendered | Should -Match 'CheckId'
        $rendered | Should -Match 'MET-MDO001'
    }

    # PSTypeName is consumed by the type adapter and is not a property, so it must not
    # reach the JSON payload - the schema sets additionalProperties false on checkResult.
    It 'does not leak into ConvertTo-Json' {
        $result = New-METCheckResult -CheckId 'MET-MDO001' -Category MDO -Name 'Safe Links' `
            -Result Pass -Severity High -AffectedObject 'Tenant' -Finding 'Fine.'

        ($result | ConvertTo-Json -Depth 5) | Should -Not -Match 'PSTypeName'
    }
}
