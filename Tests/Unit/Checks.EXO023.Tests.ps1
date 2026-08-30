BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"

    function Get-AdminAuditLogConfig { [CmdletBinding()] param() }
}

Describe 'MET-EXO023 Unified Audit Log Ingestion' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'EXO' 'MET-EXO023-UnifiedAuditLog.ps1'
    }

    Context 'UnifiedAuditLogIngestionEnabled is true' {
        BeforeAll {
            Mock Get-AdminAuditLogConfig {
                [PSCustomObject]@{ UnifiedAuditLogIngestionEnabled = $true }
            }
        }

        It 'Returns Pass' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
            $results[0].Severity | Should -Be 'High'
            $results[0].CheckId | Should -Be 'MET-EXO023'
            $results[0].Category | Should -Be 'EXO'
            $results[0].Name | Should -Be 'Unified Audit Log Ingestion'
            $results[0].Finding | Should -Match 'ingestion is enabled'
        }

        It 'States that retention is not verified by this check' {
            $results = & $checkFile
            $results[0].Recommendation | Should -Match 'does not verify audit log retention'
        }
    }

    Context 'UnifiedAuditLogIngestionEnabled is false' {
        BeforeAll {
            Mock Get-AdminAuditLogConfig {
                [PSCustomObject]@{ UnifiedAuditLogIngestionEnabled = $false }
            }
        }

        It 'Returns Fail with High severity' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'High'
            $results[0].CheckId | Should -Be 'MET-EXO023'
            $results[0].Finding | Should -Match 'ingestion is disabled'
        }

        It 'Recommends enabling ingestion' {
            $results = & $checkFile
            $results[0].Recommendation | Should -Match 'Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled \$true'
        }
    }

    Context 'UnifiedAuditLogIngestionEnabled is null' {
        BeforeAll {
            Mock Get-AdminAuditLogConfig {
                [PSCustomObject]@{ UnifiedAuditLogIngestionEnabled = $null }
            }
        }

        It 'Returns Fail and states the property was absent' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'High'
            $results[0].Finding | Should -Match 'was absent'
            $results[0].Finding | Should -Match 'could not be confirmed'
        }
    }

    Context 'UnifiedAuditLogIngestionEnabled property is absent entirely' {
        BeforeAll {
            Mock Get-AdminAuditLogConfig {
                [PSCustomObject]@{ Name = 'Admin Audit Log Settings' }
            }
        }

        It 'Returns Fail rather than assuming a safe default' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'High'
            $results[0].Finding | Should -Match 'historically shipped switched off'
        }
    }

    Context 'Get-AdminAuditLogConfig throws' {
        BeforeAll {
            Mock Get-AdminAuditLogConfig {
                throw 'Access denied'
            }
        }

        It 'Returns Fail with error message populated' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'High'
            $results[0].Error | Should -Not -BeNullOrEmpty
            $results[0].Error | Should -Match 'Access denied'
        }
    }
}
