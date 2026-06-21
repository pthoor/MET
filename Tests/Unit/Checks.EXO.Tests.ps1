BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"

    # Stub EXO/DNS cmdlets
    function Get-AcceptedDomain              { [CmdletBinding()] param() }
    function Resolve-DnsName                 { [CmdletBinding()] param([string]$Name,[string]$Type,[switch]$DnsOnly,[switch]$ErrorAction) }
    function Resolve-METDnsName             { [CmdletBinding()] param([string]$Name,[string]$Type) }
    function Get-DkimSigningConfig           { [CmdletBinding()] param() }
    function Get-QuarantinePolicy            { [CmdletBinding()] param() }
    function Get-TenantAllowBlockListItems   { [CmdletBinding()] param([string]$ListType) }
    function Get-ReportSubmissionPolicy      { [CmdletBinding()] param() }
    function Get-ReportSubmissionRule        { [CmdletBinding()] param() }
    function Get-TransportRule               { [CmdletBinding()] param([string]$ResultSize) }
}

Describe 'MET-EXO001 DMARC' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'EXO' 'MET-EXO001-DMARC.ps1'
    }

    Context 'mail.onmicrosoft.com accepted domain' {
        BeforeAll {
            Mock Get-AcceptedDomain {
                [PSCustomObject]@{ DomainName = 'contoso.mail.onmicrosoft.com'; Default = $true; DomainType = 'Authoritative' }
            }
        }

        It 'Returns NotApplicable' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'NotApplicable'
            $results[0].Severity | Should -Be 'Informational'
        }
    }

    Context 'onmicrosoft domain without DMARC record' {
        BeforeAll {
            Mock Get-AcceptedDomain {
                [PSCustomObject]@{ DomainName = 'contoso.onmicrosoft.com'; Default = $true; DomainType = 'Authoritative' }
            }
            Mock Resolve-METDnsName { throw 'DNS name not found' }
        }

        It 'Returns Fail with admin center recommendation' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Recommendation | Should -Match 'admin center'
        }
    }
}

Describe 'MET-EXO002 DKIM' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'EXO' 'MET-EXO002-DKIM.ps1'
    }

    Context 'DKIM enabled with 2048-bit key and Valid status' {
        BeforeAll {
            Mock Get-DkimSigningConfig {
                [PSCustomObject]@{ Domain = 'contoso.com'; Enabled = $true; KeySize = 2048; Status = 'Valid' }
            }
        }
        It 'Returns Pass' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
        }
    }

    Context 'DKIM is disabled' {
        BeforeAll {
            Mock Get-DkimSigningConfig {
                [PSCustomObject]@{ Domain = 'contoso.com'; Enabled = $false; KeySize = 2048; Status = 'Valid' }
            }
        }
        It 'Returns Fail' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
        }
    }

    Context 'DKIM key is 1024-bit' {
        BeforeAll {
            Mock Get-DkimSigningConfig {
                [PSCustomObject]@{ Domain = 'contoso.com'; Enabled = $true; KeySize = 1024; Status = 'Valid' }
            }
        }
        It 'Returns Fail and mentions key size' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Finding | Should -Match '1024'
        }
    }

    Context 'DKIM status is not Valid' {
        BeforeAll {
            Mock Get-DkimSigningConfig {
                [PSCustomObject]@{ Domain = 'contoso.com'; Enabled = $true; KeySize = 2048; Status = 'CnameMissing' }
            }
        }
        It 'Returns Fail and mentions status' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Finding | Should -Match 'CnameMissing'
        }
    }

    Context 'No DKIM configs found' {
        BeforeAll { Mock Get-DkimSigningConfig { @() } }
        It 'Returns Fail' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
        }
    }

    Context 'Get-DkimSigningConfig throws' {
        BeforeAll { Mock Get-DkimSigningConfig { throw 'Unauthorized' } }
        It 'Returns Fail with Error populated' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Error | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'MET-EXO004 Quarantine Policies' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'EXO' 'MET-EXO004-QuarantinePolicy.ps1'
    }

    Context 'Policy with adequate permissions and retention' {
        BeforeAll {
            Mock Get-QuarantinePolicy {
                [PSCustomObject]@{
                    Name                                = 'DefaultFullAccessPolicy'
                    EndUserQuarantinePermissionsValue   = 23
                    QuarantineRetentionDays             = 30
                }
            }
        }
        It 'Returns Pass' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
        }
    }

    Context 'Policy with zero end-user permissions' {
        BeforeAll {
            Mock Get-QuarantinePolicy {
                [PSCustomObject]@{
                    Name                                = 'AdminOnly'
                    EndUserQuarantinePermissionsValue   = 0
                    QuarantineRetentionDays             = 30
                }
            }
        }
        It 'Returns Warning' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
        }
    }

    Context 'Policy with low retention days' {
        BeforeAll {
            Mock Get-QuarantinePolicy {
                [PSCustomObject]@{
                    Name                                = 'ShortRetention'
                    EndUserQuarantinePermissionsValue   = 23
                    QuarantineRetentionDays             = 7
                }
            }
        }
        It 'Returns Warning and mentions retention' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'retention'
        }
    }
}

Describe 'MET-EXO006 Submission Policy' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'EXO' 'MET-EXO006-SubmissionPolicy.ps1'
    }

    Context 'Reporting to Microsoft enabled with submission mailbox' {
        BeforeAll {
            Mock Get-ReportSubmissionPolicy {
                [PSCustomObject]@{ EnableReportToMicrosoft = $true; EnableUserEmailNotification = $true }
            }
            Mock Get-ReportSubmissionRule {
                [PSCustomObject]@{ SentTo = 'secops@contoso.com' }
            }
        }
        It 'Returns Pass' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
        }
    }

    Context 'Reporting to Microsoft disabled' {
        BeforeAll {
            Mock Get-ReportSubmissionPolicy {
                [PSCustomObject]@{ EnableReportToMicrosoft = $false; EnableUserEmailNotification = $true }
            }
            Mock Get-ReportSubmissionRule { $null }
        }
        It 'Returns Fail' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
        }
    }

    Context 'No submission mailbox configured' {
        BeforeAll {
            Mock Get-ReportSubmissionPolicy {
                [PSCustomObject]@{ EnableReportToMicrosoft = $true; EnableUserEmailNotification = $true }
            }
            Mock Get-ReportSubmissionRule { $null }
        }
        It 'Returns Warning and mentions mailbox' {
            $results = & $checkFile
            $mailboxResult = $results | Where-Object { $_.Name -match 'SecOps Mailbox' }
            $mailboxResult | Should -Not -BeNullOrEmpty
            $mailboxResult.Result | Should -Be 'Warning'
            $mailboxResult.Finding | Should -Match 'mailbox'
        }
    }
}
