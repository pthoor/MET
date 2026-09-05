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

        It 'Returns Warning, not Pass, because the override exposure is unverified' {
            $results = @(& $checkFile)
            $results.Count | Should -Be 1
            $results[0].Result | Should -Be 'Warning'
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

    # Get-EXOCasMailbox returns $null for SmtpClientAuthenticationDisabled on a mailbox
    # that inherits the tenant setting, which the check reads as "no override". A mailbox
    # object that omits the property entirely is indistinguishable from that.
    Context 'The CAS mailbox objects omit SmtpClientAuthenticationDisabled' {
        BeforeAll {
            Mock Get-TransportConfig { [PSCustomObject]@{ SmtpClientAuthenticationDisabled = $true } }
            Mock Get-EXOCasMailbox {
                @(
                    [PSCustomObject]@{ PrimarySmtpAddress = 'a@contoso.com' }
                    [PSCustomObject]@{ PrimarySmtpAddress = 'b@contoso.com' }
                )
            }
        }

        # Pins current behaviour. An absent value here is not separated from the documented
        # $null that means "inherits the tenant setting", so the check states that no
        # mailbox re-enables SMTP AUTH on the strength of a property it may never have been
        # given. Left pinned so it cannot change unnoticed.
        It 'Currently returns Pass and claims no mailbox re-enables SMTP AUTH' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Pass'
            $results[0].Finding | Should -Match 'no mailbox explicitly re-enables it'
            $results[0].Finding | Should -Not -Match 'not returned'
        }
    }

    # SmtpClientAuthenticationDisabled $true means SMTP AUTH is OFF, which is the
    # hardened state. The property name reads as the opposite of the verdict it produces
    # at both levels - tenant-wide and per mailbox - so a refactor that "simplifies" the
    # condition inverts the result. Both senses are pinned at both levels.
    Context 'Inverted-sense regression guard' {
        It 'Passes only when SmtpClientAuthenticationDisabled is true tenant-wide and fails only when it is false' {
            Mock Get-EXOCasMailbox { @() }

            Mock Get-TransportConfig { [PSCustomObject]@{ SmtpClientAuthenticationDisabled = $true } }
            (& $checkFile)[0].Result | Should -Be 'Pass'

            Mock Get-TransportConfig { [PSCustomObject]@{ SmtpClientAuthenticationDisabled = $false } }
            (& $checkFile)[0].Result | Should -Be 'Fail'
        }

        It 'Treats a per-mailbox false as the re-enabled sense and a per-mailbox true as the disabled sense' {
            Mock Get-TransportConfig { [PSCustomObject]@{ SmtpClientAuthenticationDisabled = $true } }

            Mock Get-EXOCasMailbox {
                @([PSCustomObject]@{ PrimarySmtpAddress = 'printer@contoso.com'; SmtpClientAuthenticationDisabled = $false })
            }
            $override = (& $checkFile)[0]
            $override.Result | Should -Be 'Warning'
            $override.Finding | Should -Match 'printer@contoso.com'

            Mock Get-EXOCasMailbox {
                @([PSCustomObject]@{ PrimarySmtpAddress = 'printer@contoso.com'; SmtpClientAuthenticationDisabled = $true })
            }
            $noOverride = (& $checkFile)[0]
            $noOverride.Result | Should -Be 'Pass'
            $noOverride.Finding | Should -Not -Match 'printer@contoso.com'
        }
    }
}
