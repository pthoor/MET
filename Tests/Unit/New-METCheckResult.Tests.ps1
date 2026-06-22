BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..' '..' 'Private' 'New-METCheckResult.ps1'
    . $modulePath
    $modulePath2 = Join-Path $PSScriptRoot '..' '..' 'Private' 'Get-METCheckWeight.ps1'
    . $modulePath2
}

Describe 'New-METCheckResult' {

    Context 'Required parameters produce valid output shape' {
        It 'Returns a PSCustomObject with all expected properties' {
            $result = New-METCheckResult `
                -CheckId 'MET-MDO001' -Category MDO -Name 'Safe Links' `
                -Result Pass -Severity High `
                -AffectedObject 'Test Policy' -Finding 'All settings correct'

            $result | Should -Not -BeNullOrEmpty
            $result.PSObject.Properties.Name | Should -Contain 'CheckId'
            $result.PSObject.Properties.Name | Should -Contain 'Category'
            $result.PSObject.Properties.Name | Should -Contain 'Name'
            $result.PSObject.Properties.Name | Should -Contain 'Result'
            $result.PSObject.Properties.Name | Should -Contain 'Severity'
            $result.PSObject.Properties.Name | Should -Contain 'Score'
            $result.PSObject.Properties.Name | Should -Contain 'AffectedObject'
            $result.PSObject.Properties.Name | Should -Contain 'Finding'
            $result.PSObject.Properties.Name | Should -Contain 'Recommendation'
            $result.PSObject.Properties.Name | Should -Contain 'ReferenceUrl'
            $result.PSObject.Properties.Name | Should -Contain 'Timestamp'
            $result.PSObject.Properties.Name | Should -Contain 'Error'
        }

        It 'Sets Score to 100 for a Pass result' {
            $result = New-METCheckResult `
                -CheckId 'MET-MDO001' -Category MDO -Name 'Test' `
                -Result Pass -Severity High -AffectedObject 'Obj' -Finding 'ok'

            $result.Score | Should -Be 100
        }

        It 'Sets Score to 0 for a Fail result' {
            $result = New-METCheckResult `
                -CheckId 'MET-MDO001' -Category MDO -Name 'Test' `
                -Result Fail -Severity High -AffectedObject 'Obj' -Finding 'bad'

            $result.Score | Should -Be 0
        }

        It 'Sets Score to 50 for a Warning result' {
            $result = New-METCheckResult `
                -CheckId 'MET-MDO001' -Category MDO -Name 'Test' `
                -Result Warning -Severity Medium -AffectedObject 'Obj' -Finding 'partial'

            $result.Score | Should -Be 50
        }

        It 'Sets Score to null for NotApplicable result' {
            $result = New-METCheckResult `
                -CheckId 'MET-MDO001' -Category MDO -Name 'Test' `
                -Result NotApplicable -Severity Low -AffectedObject 'Obj' -Finding 'n/a'

            $result.Score | Should -BeNullOrEmpty
        }

        It 'Stores the Error field when provided' {
            $result = New-METCheckResult `
                -CheckId 'MET-MDO001' -Category MDO -Name 'Test' `
                -Result Fail -Severity High -AffectedObject 'Obj' -Finding 'err' `
                -ErrorMessage 'Connection refused'

            $result.Error | Should -Be 'Connection refused'
        }

        It 'Error field is null when not provided' {
            $result = New-METCheckResult `
                -CheckId 'MET-MDO001' -Category MDO -Name 'Test' `
                -Result Pass -Severity Low -AffectedObject 'Obj' -Finding 'ok'

            $result.Error | Should -BeNullOrEmpty
        }

        It 'Timestamp is a UTC datetime' {
            $before = [datetime]::UtcNow.AddSeconds(-1)
            $result = New-METCheckResult `
                -CheckId 'MET-MDO001' -Category MDO -Name 'Test' `
                -Result Pass -Severity Low -AffectedObject 'Obj' -Finding 'ok'
            $after = [datetime]::UtcNow.AddSeconds(1)

            $result.Timestamp | Should -BeGreaterThan $before
            $result.Timestamp | Should -BeLessThan $after
        }
    }

    Context 'Parameter validation' {
        It 'Throws on invalid Category' {
            { New-METCheckResult -CheckId 'X' -Category 'Invalid' -Name 'T' -Result Pass -Severity High -AffectedObject 'O' -Finding 'F' } |
                Should -Throw
        }

        It 'Throws on invalid Result' {
            { New-METCheckResult -CheckId 'X' -Category MDO -Name 'T' -Result 'Unknown' -Severity High -AffectedObject 'O' -Finding 'F' } |
                Should -Throw
        }

        It 'Throws on invalid Severity' {
            { New-METCheckResult -CheckId 'X' -Category MDO -Name 'T' -Result Pass -Severity 'VeryHigh' -AffectedObject 'O' -Finding 'F' } |
                Should -Throw
        }
    }
}

Describe 'Get-METCheckWeight' {
    It 'Returns 40 for Critical' { Get-METCheckWeight -Severity Critical | Should -Be 40 }
    It 'Returns 20 for High'     { Get-METCheckWeight -Severity High     | Should -Be 20 }
    It 'Returns 10 for Medium'   { Get-METCheckWeight -Severity Medium   | Should -Be 10 }
    It 'Returns 5 for Low'       { Get-METCheckWeight -Severity Low      | Should -Be 5  }
    It 'Returns 0 for Informational' { Get-METCheckWeight -Severity Informational | Should -Be 0 }
}
