BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"

    function Get-OrganizationConfig { [CmdletBinding()] param() }
}

Describe 'MET-EXO021 Mailbox Audit Logging' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'EXO' 'MET-EXO021-MailboxAuditing.ps1'
    }

    Context 'AuditDisabled is false (mailbox auditing is on)' {
        BeforeAll {
            Mock Get-OrganizationConfig {
                [PSCustomObject]@{ AuditDisabled = $false }
            }
        }

        It 'Returns Pass' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].CheckId | Should -Be 'MET-EXO021'
            $results[0].Category | Should -Be 'EXO'
            $results[0].Name | Should -Be 'Mailbox Audit Logging'
            $results[0].Finding | Should -Match 'enabled organization-wide'
        }
    }

    Context 'AuditDisabled is true (mailbox auditing is off)' {
        BeforeAll {
            Mock Get-OrganizationConfig {
                [PSCustomObject]@{ AuditDisabled = $true }
            }
        }

        It 'Returns Fail with Medium severity' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].CheckId | Should -Be 'MET-EXO021'
            $results[0].Finding | Should -Match 'turned off organization-wide'
        }

        It 'Recommends re-enabling auditing' {
            $results = & $checkFile
            $results[0].Recommendation | Should -Match 'Set-OrganizationConfig -AuditDisabled \$false'
            $results[0].Recommendation | Should -Match 'AuditEnabled'
        }
    }

    Context 'AuditDisabled is null' {
        BeforeAll {
            Mock Get-OrganizationConfig {
                [PSCustomObject]@{ AuditDisabled = $null }
            }
        }

        It 'Returns Pass and states the value was assumed from the platform default' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].Finding | Should -Match 'absent'
            $results[0].Finding | Should -Match 'platform default'
        }
    }

    Context 'AuditDisabled property is absent entirely' {
        BeforeAll {
            Mock Get-OrganizationConfig {
                [PSCustomObject]@{ Name = 'contoso.onmicrosoft.com' }
            }
        }

        It 'Returns Pass and states the value was assumed from the platform default' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].Finding | Should -Match 'assumed'
        }
    }

    Context 'Get-OrganizationConfig throws' {
        BeforeAll {
            Mock Get-OrganizationConfig {
                throw 'Access denied'
            }
        }

        It 'Returns Fail with error message populated' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].Error | Should -Not -BeNullOrEmpty
            $results[0].Error | Should -Match 'Access denied'
        }
    }

    Context 'Inverted-sense regression guard' {
        It 'Fails only when AuditDisabled is true and passes only when it is false' {
            Mock Get-OrganizationConfig { [PSCustomObject]@{ AuditDisabled = $true } }
            (& $checkFile)[0].Result | Should -Be 'Fail'

            Mock Get-OrganizationConfig { [PSCustomObject]@{ AuditDisabled = $false } }
            (& $checkFile)[0].Result | Should -Be 'Pass'
        }
    }
}
