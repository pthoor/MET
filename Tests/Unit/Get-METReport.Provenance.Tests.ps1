BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    Import-Module (Join-Path $root 'MET.psd1') -Force

    function global:Get-AcceptedDomain { [CmdletBinding()] param() }

    function New-StampedResult {
        param([string] $Tenant)
        [PSCustomObject]@{
            CheckId        = 'MET-EXO001'
            Category       = 'EXO'
            Name           = 'DMARC Record'
            Result         = 'Fail'
            Severity       = 'High'
            Score          = 0
            AffectedObject = 'contoso.com'
            Finding        = 'DMARC policy is p=none'
            Recommendation = 'Move to p=quarantine'
            ReferenceUrl   = ''
            Timestamp      = [datetime]::UtcNow
            Error          = $null
            Metadata       = @{ METRunTenant = $Tenant }
        }
    }
}

AfterAll {
    Remove-Item function:global:Get-AcceptedDomain -ErrorAction SilentlyContinue
    InModuleScope MET { $script:METSessionInfo = $null }
}

Describe 'Get-METReport tenant provenance' {
    Context 'Results carry provenance and the live connection reports a different tenant' {
        BeforeAll {
            Mock Get-AcceptedDomain {
                [PSCustomObject]@{ DomainName = 'customer-b.onmicrosoft.com'; Default = $true }
            } -ModuleName MET
        }

        It 'Labels the report with the tenant the results were gathered under' {
            $out = New-StampedResult -Tenant 'customer-a.onmicrosoft.com' |
                Get-METReport -Format JSON -WarningAction SilentlyContinue |
                ConvertFrom-Json
            $out.tenant | Should -Be 'customer-a.onmicrosoft.com'
        }

        It 'Warns that the live session disagrees, naming both tenants' {
            $warnings = @()
            New-StampedResult -Tenant 'customer-a.onmicrosoft.com' |
                Get-METReport -Format JSON -WarningVariable warnings -WarningAction SilentlyContinue |
                Out-Null
            ($warnings -join ' ') | Should -Match 'customer-a\.onmicrosoft\.com'
            ($warnings -join ' ') | Should -Match 'customer-b\.onmicrosoft\.com'
        }

        It 'Suppresses the authentication block, since it would describe the wrong tenant''s session' {
            InModuleScope MET {
                $script:METSessionInfo = [PSCustomObject]@{
                    AuthMode          = 'Interactive'
                    DeviceCodeUsed    = $false
                    TenantIdentity    = 'customer-b.onmicrosoft.com'
                    ServicesConnected = @('ExchangeOnline')
                    ConnectedAtUtc    = [datetime]::UtcNow
                }
            }

            $out = New-StampedResult -Tenant 'customer-a.onmicrosoft.com' |
                Get-METReport -Format JSON -WarningAction SilentlyContinue |
                ConvertFrom-Json

            $out.authentication | Should -BeNullOrEmpty
        }
    }

    Context 'Results carry provenance and the live connection reports the same tenant' {
        BeforeAll {
            Mock Get-AcceptedDomain {
                [PSCustomObject]@{ DomainName = 'customer-a.onmicrosoft.com'; Default = $true }
            } -ModuleName MET
        }

        It 'Still populates the authentication block' {
            InModuleScope MET {
                $script:METSessionInfo = [PSCustomObject]@{
                    AuthMode          = 'Interactive'
                    DeviceCodeUsed    = $false
                    TenantIdentity    = 'customer-a.onmicrosoft.com'
                    ServicesConnected = @('ExchangeOnline')
                    ConnectedAtUtc    = [datetime]::UtcNow
                }
            }

            $out = New-StampedResult -Tenant 'customer-a.onmicrosoft.com' |
                Get-METReport -Format JSON -WarningAction SilentlyContinue |
                ConvertFrom-Json

            $out.authentication | Should -Not -BeNullOrEmpty
            $out.authentication.authMode | Should -Be 'Interactive'
        }
    }

    Context 'Explicit -TenantName always wins' {
        BeforeAll {
            Mock Get-AcceptedDomain {
                [PSCustomObject]@{ DomainName = 'customer-b.onmicrosoft.com'; Default = $true }
            } -ModuleName MET
        }

        It 'Uses the caller-supplied name over both provenance and the live session' {
            $out = New-StampedResult -Tenant 'customer-a.onmicrosoft.com' |
                Get-METReport -Format JSON -TenantName 'explicit.example.com' -WarningAction SilentlyContinue |
                ConvertFrom-Json
            $out.tenant | Should -Be 'explicit.example.com'
        }
    }

    Context 'Results carry no provenance' {
        BeforeAll {
            Mock Get-AcceptedDomain {
                [PSCustomObject]@{ DomainName = 'customer-b.onmicrosoft.com'; Default = $true }
            } -ModuleName MET
        }

        It 'Falls back to the live connection and does not warn' {
            $r = New-StampedResult -Tenant 'customer-a.onmicrosoft.com'
            $r.Metadata = $null
            $warnings = @()
            $out = $r | Get-METReport -Format JSON -WarningVariable warnings -WarningAction SilentlyContinue |
                ConvertFrom-Json
            $out.tenant | Should -Be 'customer-b.onmicrosoft.com'
            ($warnings | Where-Object { $_ -match 'tenant' }) | Should -BeNullOrEmpty
        }
    }
}
