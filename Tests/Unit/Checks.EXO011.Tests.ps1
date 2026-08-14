BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"
    function Get-InboundConnector { [CmdletBinding()] param() }
}

Describe 'MET-EXO011 Mail Flow Connector Hygiene' {
    BeforeEach {
        $checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'EXO' 'MET-EXO011-ConnectorHygiene.ps1'
    }

    Context 'no enabled connectors' {
        BeforeAll {
            Mock Get-InboundConnector { @() }
        }
        It 'Returns Info' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Info'
            $results[0].Severity | Should -Be 'High'
        }
    }

    Context 'well-configured connector (RequireTls true, sender IPs restricted)' {
        BeforeAll {
            Mock Get-InboundConnector {
                [PSCustomObject]@{
                    Name                     = 'PartnerConnector'
                    Enabled                  = $true
                    ConnectorType            = 'Partner'
                    RequireTls               = $true
                    SenderIPAddresses        = @('203.0.113.5')
                    SenderDomains            = @()
                    RestrictDomainsToIPAddresses = $true
                    RestrictDomainsToCertificate = $false
                    TlsSenderCertificateName = 'partner.contoso.com'
                }
            }
        }
        It 'Returns Pass' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
        }
    }

    Context 'connector missing RequireTls' {
        BeforeAll {
            Mock Get-InboundConnector {
                [PSCustomObject]@{
                    Name                     = 'LegacyConnector'
                    Enabled                  = $true
                    ConnectorType            = 'OnPremises'
                    RequireTls               = $false
                    SenderIPAddresses        = @('203.0.113.10')
                    SenderDomains            = @()
                    RestrictDomainsToIPAddresses = $true
                    RestrictDomainsToCertificate = $false
                    TlsSenderCertificateName = $null
                }
            }
        }
        It 'Returns Warning and mentions the connector name and missing TLS' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match "'LegacyConnector'"
            $results[0].Finding | Should -Match 'does not require TLS'
        }
    }

    Context 'connector with no sender restriction' {
        BeforeAll {
            Mock Get-InboundConnector {
                [PSCustomObject]@{
                    Name                     = 'OpenConnector'
                    Enabled                  = $true
                    ConnectorType            = 'Partner'
                    RequireTls               = $true
                    SenderIPAddresses        = @()
                    SenderDomains            = @()
                    RestrictDomainsToIPAddresses = $false
                    RestrictDomainsToCertificate = $false
                    TlsSenderCertificateName = $null
                }
            }
        }
        It 'Returns Warning and mentions no sender restriction' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'no authenticated sender IP or TLS certificate restriction'
        }
    }

    Context 'disabled connector with bad settings is ignored' {
        BeforeAll {
            Mock Get-InboundConnector {
                [PSCustomObject]@{
                    Name                     = 'DisabledConnector'
                    Enabled                  = $false
                    ConnectorType            = 'OnPremises'
                    RequireTls               = $false
                    SenderIPAddresses        = @()
                    SenderDomains            = @()
                    RestrictDomainsToIPAddresses = $false
                    RestrictDomainsToCertificate = $false
                    TlsSenderCertificateName = $null
                }
            }
        }
        It 'Returns Info since there are no enabled connectors' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Info'
        }
    }

    Context 'connector scoped only by sender domain' {
        BeforeAll {
            Mock Get-InboundConnector {
                [PSCustomObject]@{
                    Name                         = 'DomainOnlyConnector'
                    Enabled                      = $true
                    ConnectorType                = 'Partner'
                    RequireTls                   = $true
                    SenderIPAddresses            = @()
                    SenderDomains                = @('partner.example')
                    RestrictDomainsToIPAddresses = $false
                    RestrictDomainsToCertificate = $false
                    TlsSenderCertificateName     = $null
                }
            }
        }
        It 'Returns Warning because sender domains do not authenticate the source' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'SenderDomains does not authenticate'
        }
    }

    Context 'connector authenticated by TLS sender certificate' {
        BeforeAll {
            Mock Get-InboundConnector {
                [PSCustomObject]@{
                    Name                         = 'CertificateConnector'
                    Enabled                      = $true
                    ConnectorType                = 'Partner'
                    RequireTls                   = $true
                    SenderIPAddresses            = @()
                    SenderDomains                = @('partner.example')
                    RestrictDomainsToIPAddresses = $false
                    RestrictDomainsToCertificate = $true
                    TlsSenderCertificateName     = '*.partner.example'
                }
            }
        }
        It 'Returns Pass without sender IP addresses' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Pass'
        }
    }

    Context 'cmdlet throws' {
        BeforeAll {
            Mock Get-InboundConnector { throw 'Access denied' }
        }
        It 'Returns Fail with Error populated' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Fail'
            $results[0].Error | Should -Not -BeNullOrEmpty
        }
    }
}
