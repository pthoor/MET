BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Private/New-METCheckResult.ps1"
    . "$root/Private/Get-METCheckWeight.ps1"
    function Get-InboundConnector { [CmdletBinding()] param() }
}

Describe 'MET-EXO011 Mail Flow Connector Hygiene' {
    BeforeEach {
        $script:checkFile = Join-Path $PSScriptRoot '..' '..' 'Checks' 'EXO' 'MET-EXO011-ConnectorHygiene.ps1'
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

    Context 'connector with certificate name but no certificate restriction' {
        BeforeAll {
            Mock Get-InboundConnector {
                [PSCustomObject]@{
                    Name                         = 'LooseCertificateConnector'
                    Enabled                      = $true
                    ConnectorType                = 'Partner'
                    RequireTls                   = $true
                    SenderIPAddresses            = @()
                    SenderDomains                = @('partner.example')
                    RestrictDomainsToIPAddresses = $false
                    RestrictDomainsToCertificate = $false
                    TlsSenderCertificateName     = '*.partner.example'
                }
            }
        }
        It 'Returns Warning because the certificate name is not bound to authentication' {
            $results = & $checkFile
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match 'RestrictDomainsToCertificate'
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

    # The enabled-connector filter is Enabled -eq $true. A connector object that omits
    # Enabled, or returns it as $null, is neither enabled nor disabled - it must still be
    # assessed, since its remaining settings (RequireTls, IP/certificate binding) are still
    # readable and still matter, and its enabled state is reported as not established
    # rather than assumed.
    Context 'a connector omits the Enabled property' {
        BeforeAll {
            Mock Get-InboundConnector {
                [PSCustomObject]@{
                    Name              = 'LegacyConnector'
                    ConnectorType     = 'OnPremises'
                    RequireTls        = $false
                    SenderIPAddresses = @()
                    SenderDomains     = @('vendor.com')
                }
            }
        }

        It 'Assesses the connector instead of reporting no enabled connectors found' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Not -Match 'No enabled inbound connectors found'
            $results[0].Finding | Should -Match "'LegacyConnector'"
            $results[0].Finding | Should -Match 'Enabled property was not returned'
            $results[0].Finding | Should -Match 'not established'
            $results[0].Finding | Should -Match 'does not require TLS'
            $results[0].Error | Should -Not -BeNullOrEmpty
        }
    }

    Context 'one enabled connector plus one unknown-state connector' {
        BeforeAll {
            Mock Get-InboundConnector {
                @(
                    [PSCustomObject]@{
                        Name                         = 'GoodConnector'
                        Enabled                      = $true
                        RequireTls                   = $true
                        SenderIPAddresses            = @('203.0.113.5')
                        SenderDomains                = @()
                        RestrictDomainsToIPAddresses = $true
                        RestrictDomainsToCertificate = $false
                        TlsSenderCertificateName     = $null
                    }
                    [PSCustomObject]@{
                        Name                         = 'UnknownConnector'
                        RequireTls                   = $true
                        SenderIPAddresses            = @('203.0.113.9')
                        SenderDomains                = @()
                        RestrictDomainsToIPAddresses = $true
                        RestrictDomainsToCertificate = $false
                        TlsSenderCertificateName     = $null
                    }
                )
            }
        }

        It 'Assesses both the enabled connector and the unknown-state connector' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Warning'
            $results[0].AffectedObject | Should -Match '1 enabled'
            $results[0].AffectedObject | Should -Match '1 with enabled state not established'
            $results[0].Finding | Should -Match "'UnknownConnector'"
            $results[0].Finding | Should -Not -Match "'GoodConnector' does not require TLS"
        }
    }

    Context 'an enabled connector omits every authentication property' {
        BeforeAll {
            Mock Get-InboundConnector {
                [PSCustomObject]@{ Name = 'BareConnector'; Enabled = $true }
            }
        }

        It 'Returns Warning naming the connector rather than passing it' {
            $results = @(& $checkFile)
            $results[0].Result | Should -Be 'Warning'
            $results[0].Finding | Should -Match "'BareConnector'"
            $results[0].Finding | Should -Match 'does not require TLS'
        }
    }

    # RequireTls is asserted with -ne $true while the two binding tests beside it are
    # asserted with -eq $true. Normalising the three onto one form would flip this one.
    Context 'Inverted-sense regression guard' {
        It 'Raises the TLS issue only when RequireTls is false' {
            Mock Get-InboundConnector {
                [PSCustomObject]@{
                    Name                         = 'PartnerConnector'
                    Enabled                      = $true
                    RequireTls                   = $true
                    SenderIPAddresses            = @('203.0.113.10')
                    SenderDomains                = @()
                    RestrictDomainsToIPAddresses = $true
                    RestrictDomainsToCertificate = $false
                    TlsSenderCertificateName     = $null
                }
            }
            $secure = (& $checkFile)[0]
            $secure.Result | Should -Be 'Pass'
            $secure.Finding | Should -Not -Match 'does not require TLS'

            Mock Get-InboundConnector {
                [PSCustomObject]@{
                    Name                         = 'PartnerConnector'
                    Enabled                      = $true
                    RequireTls                   = $false
                    SenderIPAddresses            = @('203.0.113.10')
                    SenderDomains                = @()
                    RestrictDomainsToIPAddresses = $true
                    RestrictDomainsToCertificate = $false
                    TlsSenderCertificateName     = $null
                }
            }
            $insecure = (& $checkFile)[0]
            $insecure.Result | Should -Be 'Warning'
            $insecure.Finding | Should -Match "'PartnerConnector' does not require TLS"
        }
    }
}
