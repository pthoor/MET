BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Public/Connect-METSession.ps1"
    . "$root/Private/Get-METCertificateByThumbprint.ps1"

    # Stubs mirror the real cmdlets' parameter names so that splatting a
    # non-existent parameter fails binding instead of silently passing.
    function Connect-MicrosoftTeams {
        [CmdletBinding()]
        param(
            [string] $AccountId,
            [string] $TenantId,
            [switch] $UseDeviceAuthentication,
            [switch] $DisableWAM,
            [string] $ApplicationId,
            [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,
            [switch] $Identity
        )
    }
    function Get-CsTenant { [CmdletBinding()] param() }
    function Connect-MgGraph { [CmdletBinding()] param() }
    function Get-MgContext { [CmdletBinding()] param() }
    function Connect-ExchangeOnline { [CmdletBinding()] param() }
    function Get-ConnectionInformation { [CmdletBinding()] param() }
}

Describe 'Connect-METSession Teams leg' {
    BeforeEach {
        Mock Get-Module {
            [PSCustomObject]@{ Name = 'MicrosoftTeams'; Version = [version]'7.9.0' }
        } -ParameterFilter { $ListAvailable -and $Name -eq 'MicrosoftTeams' }

        Mock Import-Module {}
        Mock Connect-MicrosoftTeams {}
        Mock Get-CsTenant { throw [System.UnauthorizedAccessException]::new('Session is not established') }
    }

    Context 'Interactive with -UseDeviceAuthentication' {
        It 'Forwards UseDeviceAuthentication to Connect-MicrosoftTeams' {
            Connect-METSession -SkipGraph -SkipExchangeOnline -UseDeviceAuthentication

            Should -Invoke Connect-MicrosoftTeams -Times 1 -Exactly -ParameterFilter {
                $UseDeviceAuthentication -eq $true
            }
        }
    }

    Context 'Interactive with -UserPrincipalName' {
        It 'Forwards the UPN as AccountId' {
            Connect-METSession -SkipGraph -SkipExchangeOnline -UserPrincipalName 'admin@contoso.com'

            Should -Invoke Connect-MicrosoftTeams -Times 1 -Exactly -ParameterFilter {
                $AccountId -eq 'admin@contoso.com'
            }
        }
    }

    Context 'Already connected' {
        It 'Does not call Connect-MicrosoftTeams when Get-CsTenant succeeds' {
            Mock Get-CsTenant { [PSCustomObject]@{ TenantId = '00000000-0000-0000-0000-000000000000' } }

            Connect-METSession -SkipGraph -SkipExchangeOnline -UseDeviceAuthentication

            Should -Invoke Connect-MicrosoftTeams -Times 0 -Exactly
        }
    }

    Context 'Service principal with certificate' {
        It 'Resolves the thumbprint to an X509Certificate2 and passes -Certificate' {
            $fakeCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new()
            Mock Get-METCertificateByThumbprint { $fakeCert }

            Connect-METSession -SkipGraph -SkipExchangeOnline `
                -AppId '11111111-1111-1111-1111-111111111111' `
                -TenantId '00000000-0000-0000-0000-000000000000' `
                -CertificateThumbprint 'ABCDEF0123456789ABCDEF0123456789ABCDEF01'

            Should -Invoke Connect-MicrosoftTeams -Times 1 -Exactly -ParameterFilter {
                $ApplicationId -eq '11111111-1111-1111-1111-111111111111' -and
                $null -ne $Certificate
            }
        }
    }

    Context 'Managed identity' {
        It 'Passes -Identity rather than -ManagedIdentity' {
            Connect-METSession -SkipGraph -SkipExchangeOnline -ManagedIdentity

            Should -Invoke Connect-MicrosoftTeams -Times 1 -Exactly -ParameterFilter {
                $Identity -eq $true
            }
        }
    }
}
