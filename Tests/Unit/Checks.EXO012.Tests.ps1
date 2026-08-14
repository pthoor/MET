BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"
    function Get-EXOMailbox { [CmdletBinding()] param([string]$ResultSize,[string[]]$Properties,[string]$Filter) }
}

Describe 'MET-EXO012 Mailbox Forwarding' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'EXO' 'MET-EXO012-MailboxForwarding.ps1'
    }

    Context 'no mailboxes with forwarding' {
        BeforeAll {
            Mock Get-EXOMailbox { @() }
        }
        It 'Returns Info' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Info'
            $results[0].Severity | Should -Be 'Critical'
        }
    }

    Context 'mailbox with visible forwarding (DeliverToMailboxAndForward true)' {
        BeforeAll {
            Mock Get-EXOMailbox {
                [PSCustomObject]@{
                    PrimarySmtpAddress        = 'alice@contoso.com'
                    ForwardingSmtpAddress     = 'smtp:alice@external.com'
                    ForwardingAddress         = $null
                    DeliverToMailboxAndForward = $true
                }
            }
        }
        It 'Returns Warning, Finding shows the address mapping, no silent marker' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Severity | Should -Be 'Critical'
            $results[0].Finding | Should -Match 'alice@contoso.com -> smtp:alice@external.com'
            $results[0].Finding | Should -Not -Match '\[silent'
        }
    }

    Context 'mailbox with silent forwarding (DeliverToMailboxAndForward false)' {
        BeforeAll {
            Mock Get-EXOMailbox {
                [PSCustomObject]@{
                    PrimarySmtpAddress        = 'bob@contoso.com'
                    ForwardingSmtpAddress     = $null
                    ForwardingAddress         = 'external-user@evil.com'
                    DeliverToMailboxAndForward = $false
                }
            }
        }
        It 'Returns Warning, Finding includes silent marker' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'bob@contoso.com -> external-user@evil.com \[silent - no local copy retained\]'
        }
    }

    Context 'more than 10 forwarding mailboxes' {
        BeforeAll {
            Mock Get-EXOMailbox {
                1..12 | ForEach-Object {
                    [PSCustomObject]@{
                        PrimarySmtpAddress        = "user$_@contoso.com"
                        ForwardingSmtpAddress     = "user$_@external.com"
                        ForwardingAddress         = $null
                        DeliverToMailboxAndForward = $true
                    }
                }
            }
        }
        It 'Returns Warning and truncates sample with "and 2 more"' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].AffectedObject | Should -Match '12 with forwarding'
            $results[0].Finding | Should -Match 'and 2 more'
        }
    }

    Context 'cmdlet throws' {
        BeforeAll {
            Mock Get-EXOMailbox { throw 'Access denied' }
        }
        It 'Returns Fail with Error populated' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Error | Should -Not -BeNullOrEmpty
        }
    }
}
