BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"

    function Get-TransportConfig { [CmdletBinding()] param() }
    function Get-EXOCasMailbox { [CmdletBinding()] param($ResultSize, $Properties) }
}

Describe 'MET-EXO019 SMTP Client Authentication' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'EXO' 'MET-EXO019-SmtpAuthentication.ps1'
    }

    Context 'SMTP AUTH disabled tenant-wide with no mailbox overrides' {
        BeforeAll {
            Mock Get-TransportConfig { [PSCustomObject]@{ SmtpClientAuthenticationDisabled = $true } }
            Mock Get-EXOCasMailbox {
                @(
                    [PSCustomObject]@{ PrimarySmtpAddress = 'a@contoso.com'; SmtpClientAuthenticationDisabled = $null }
                    [PSCustomObject]@{ PrimarySmtpAddress = 'b@contoso.com'; SmtpClientAuthenticationDisabled = $true }
                )
            }
        }

        It 'Returns Pass' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Pass'
            $results[0].Severity | Should -Be 'High'
            $results[0].CheckId | Should -Be 'MET-EXO019'
            $results[0].Finding | Should -Match 'no mailbox explicitly re-enables it'
        }
    }

    Context 'SMTP AUTH enabled tenant-wide' {
        BeforeAll {
            Mock Get-TransportConfig { [PSCustomObject]@{ SmtpClientAuthenticationDisabled = $false } }
            Mock Get-EXOCasMailbox { throw 'should not be called' }
        }

        It 'Returns Fail with High severity' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'High'
            $results[0].CheckId | Should -Be 'MET-EXO019'
            $results[0].Finding | Should -Match 'enabled tenant-wide'
            $results[0].Recommendation | Should -Match 'Set-TransportConfig'
        }

        It 'Does not enumerate mailboxes' {
            $null = & $checkFile
            Should -Invoke Get-EXOCasMailbox -Times 0 -Exactly
        }
    }

    Context 'SmtpClientAuthenticationDisabled is null on the transport config' {
        BeforeAll {
            Mock Get-TransportConfig { [PSCustomObject]@{ SmtpClientAuthenticationDisabled = $null } }
            Mock Get-EXOCasMailbox { throw 'should not be called' }
        }

        It 'Returns Fail' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'High'
        }
    }

    Context 'SmtpClientAuthenticationDisabled property is missing from the transport config' {
        BeforeAll {
            Mock Get-TransportConfig { [PSCustomObject]@{ MaxReceiveSize = '35 MB' } }
            Mock Get-EXOCasMailbox { throw 'should not be called' }
        }

        It 'Returns Fail' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'High'
        }
    }

    Context 'Mailboxes explicitly re-enable SMTP AUTH' {
        BeforeAll {
            Mock Get-TransportConfig { [PSCustomObject]@{ SmtpClientAuthenticationDisabled = $true } }
            Mock Get-EXOCasMailbox {
                @(
                    [PSCustomObject]@{ PrimarySmtpAddress = 'scanner@contoso.com'; SmtpClientAuthenticationDisabled = $false }
                    [PSCustomObject]@{ PrimarySmtpAddress = 'clean@contoso.com'; SmtpClientAuthenticationDisabled = $null }
                    [PSCustomObject]@{ PrimarySmtpAddress = 'app@contoso.com'; SmtpClientAuthenticationDisabled = $false }
                )
            }
        }

        It 'Returns Warning listing the overriding mailboxes' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Warning'
            $results[0].Severity | Should -Be 'High'
            $results[0].Finding | Should -Match 'scanner@contoso\.com'
            $results[0].Finding | Should -Match 'app@contoso\.com'
            $results[0].Finding | Should -Not -Match 'clean@contoso\.com'
            $results[0].AffectedObject | Should -Match '2 mailboxes'
        }
    }

    Context 'More than ten mailboxes re-enable SMTP AUTH' {
        BeforeAll {
            Mock Get-TransportConfig { [PSCustomObject]@{ SmtpClientAuthenticationDisabled = $true } }
            Mock Get-EXOCasMailbox {
                1..25 | ForEach-Object {
                    [PSCustomObject]@{ PrimarySmtpAddress = "user$_@contoso.com"; SmtpClientAuthenticationDisabled = $false }
                }
            }
        }

        It 'Truncates the listing to ten and reports the full count' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match '25 mailbox\(es\) explicitly re-enable it'
            $results[0].Finding | Should -Match 'showing first 10 of 25'
            $results[0].Finding | Should -Not -Match 'user11@contoso\.com'
        }
    }

    Context 'Get-EXOCasMailbox throws' {
        BeforeAll {
            Mock Get-TransportConfig { [PSCustomObject]@{ SmtpClientAuthenticationDisabled = $true } }
            Mock Get-EXOCasMailbox { throw 'Insufficient permissions to read mailbox settings' }
        }

        It 'Still returns Pass for the tenant-wide setting and degrades non-fatally' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Pass'
            $results[0].Severity | Should -Be 'High'
            $results[0].Finding | Should -Match 'Per-mailbox overrides could not be enumerated'
            $results[0].Error | Should -Match 'Insufficient permissions to read mailbox settings'
        }
    }

    Context 'Get-EXOCasMailbox returns no mailboxes' {
        BeforeAll {
            Mock Get-TransportConfig { [PSCustomObject]@{ SmtpClientAuthenticationDisabled = $true } }
            Mock Get-EXOCasMailbox { @() }
        }

        It 'Returns Pass' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Pass'
            $results[0].Error | Should -BeNullOrEmpty
        }
    }

    Context 'Get-TransportConfig throws' {
        BeforeAll {
            Mock Get-TransportConfig { throw 'Access denied' }
            Mock Get-EXOCasMailbox { throw 'should not be called' }
        }

        It 'Returns Fail with the error message populated' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'High'
            $results[0].AffectedObject | Should -Be 'Transport Configuration'
            $results[0].Error | Should -Not -BeNullOrEmpty
            $results[0].Error | Should -Match 'Access denied'
        }
    }
}
