BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Public/Connect-METSession.ps1"
    . "$root/Private/Get-METCertificateByThumbprint.ps1"
    . "$root/Private/Get-METAssemblyFileVersion.ps1"
    . "$root/Private/Test-METAssemblyLoadConflict.ps1"

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
    function Get-MgContext { [CmdletBinding()] param() }
    function Get-ConnectionInformation { [CmdletBinding()] param() }

    function Connect-MgGraph {
        [CmdletBinding()]
        param(
            [string[]] $Scopes,
            [switch] $NoWelcome,
            [switch] $UseDeviceCode,
            [string] $ClientId,
            [string] $TenantId,
            [string] $CertificateThumbprint,
            [switch] $Identity
        )
    }

    # Captured before any Mock replaces it, so a mock can delegate to the real
    # implementation while injecting a synthetic loaded-assembly list.
    $script:RealTestAssemblyLoadConflict = (Get-Command Test-METAssemblyLoadConflict).ScriptBlock

    function New-FakeLoadedAssembly {
        param(
            [string] $Name,
            [string] $Version,
            [string] $Location
        )

        $nameObject = [PSCustomObject]@{ Name = $Name; Version = [version]$Version }
        $fake = [PSCustomObject]@{ Location = $Location }
        $fake | Add-Member -MemberType ScriptMethod -Name GetName -Value { $nameObject }.GetNewClosure()
        $fake
    }

    function Connect-ExchangeOnline {
        [CmdletBinding()]
        param(
            [switch] $ShowBanner,
            [switch] $ShowProgress,
            [switch] $SkipLoadingFormatData,
            [switch] $SkipLoadingCmdletHelp,
            [string] $UserPrincipalName,
            [switch] $DisableWAM,
            [switch] $Device,
            [string] $DelegatedOrganization,
            [string] $AppId,
            [string] $Organization,
            [switch] $ManagedIdentity,
            [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate
        )
    }
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

    Context 'Teams connection fails' {
        It 'Warns with actionable guidance and does not throw' {
            Mock Connect-MicrosoftTeams {
                throw [System.DllNotFoundException]::new("Unable to load shared library 'kernel32.dll'")
            }

            # -WarningVariable would bind inside the Should scriptblock's own scope,
            # so capture the warning stream by redirection instead.
            $script:teamsWarnings = @()
            {
                $script:teamsWarnings = @(
                    Connect-METSession -SkipGraph -SkipExchangeOnline -WarningAction Continue 3>&1
                )
            } | Should -Not -Throw

            ($script:teamsWarnings -join ' ') | Should -Match 'UseDeviceAuthentication'
        }
    }

    Context 'Importing MicrosoftTeams fails' {
        It 'Warns and continues rather than aborting the whole session' {
            Mock Import-Module { throw 'Could not load file or assembly Microsoft.Identity.Client' } `
                -ParameterFilter { $Name -eq 'MicrosoftTeams' }

            $script:teamsWarnings = @()
            {
                $script:teamsWarnings = @(
                    Connect-METSession -SkipGraph -SkipExchangeOnline -WarningAction Continue 3>&1
                )
            } | Should -Not -Throw

            ($script:teamsWarnings -join ' ') | Should -Match 'Failed to connect to Microsoft Teams'
            Should -Invoke Connect-MicrosoftTeams -Times 0 -Exactly
        }
    }
}

Describe 'Connect-METSession Graph leg' {
    BeforeEach {
        Mock Get-Module {
            [PSCustomObject]@{ Name = $Name; Version = [version]'2.39.0' }
        } -ParameterFilter { $ListAvailable -and $Name -like 'Microsoft.Graph*' }

        Mock Get-MgContext { $null }
        Mock Connect-MgGraph {}
    }

    Context 'Graph connection throws' {
        It 'Warns with actionable guidance and does not throw' {
            Mock Connect-MgGraph { throw 'Method not found: some MSAL API mismatch' }

            $script:graphWarnings = @()
            {
                $script:graphWarnings = @(
                    Connect-METSession -SkipExchangeOnline -SkipTeams -WarningAction Continue 3>&1
                )
            } | Should -Not -Throw

            ($script:graphWarnings -join ' ') | Should -Match 'Failed to connect to Microsoft Graph'
        }
    }

    Context 'Required Graph modules are missing' {
        It 'Warns and does not throw, and never calls Connect-MgGraph' {
            Mock Get-Module {
                $null
            } -ParameterFilter { $ListAvailable -and $Name -like 'Microsoft.Graph*' }

            $script:graphWarnings = @()
            {
                $script:graphWarnings = @(
                    Connect-METSession -SkipExchangeOnline -SkipTeams -WarningAction Continue 3>&1
                )
            } | Should -Not -Throw

            ($script:graphWarnings -join ' ') | Should -Match 'Microsoft.Graph'
            Should -Invoke Connect-MgGraph -Times 0 -Exactly
        }
    }

    Context 'Already connected' {
        It 'Does not call Connect-MgGraph when Get-MgContext succeeds' {
            Mock Get-MgContext { [PSCustomObject]@{ Account = 'admin@contoso.com' } }

            Connect-METSession -SkipExchangeOnline -SkipTeams

            Should -Invoke Connect-MgGraph -Times 0 -Exactly
        }
    }

    Context 'A newer MSAL than Graph requires is already loaded' {
        It 'Still connects - a higher loaded version is not a conflict' {
            Mock Get-Module {
                [PSCustomObject]@{
                    Name       = $Name
                    Version    = [version]'2.39.0'
                    ModuleBase = '/fake/Microsoft.Graph.Authentication/2.39.0'
                }
            } -ParameterFilter { $ListAvailable -and $Name -like 'Microsoft.Graph*' }

            # Graph ships MSAL 4.82.1.0; Exchange Online already loaded 4.83.1.0.
            Mock Get-METAssemblyFileVersion { [version]'4.82.1.0' }
            Mock Test-METAssemblyLoadConflict {
                $loaded = @(
                    New-FakeLoadedAssembly -Name 'Microsoft.Identity.Client' `
                        -Version '4.83.1.0' -Location '/exo/Microsoft.Identity.Client.dll'
                )
                & $script:RealTestAssemblyLoadConflict -AssemblyName $AssemblyName `
                    -RequiredVersion $RequiredVersion -LoadedAssemblies $loaded
            }

            $script:graphWarnings = @()
            {
                $script:graphWarnings = @(
                    Connect-METSession -SkipExchangeOnline -SkipTeams -WarningAction Continue 3>&1
                )
            } | Should -Not -Throw

            Should -Invoke Connect-MgGraph -Times 1 -Exactly
            ($script:graphWarnings -join ' ') | Should -Not -Match 'already active in this PowerShell session'
        }
    }
}

Describe 'Connect-METSession assembly conflict detection' {
    BeforeEach {
        Mock Get-Module {
            [PSCustomObject]@{ Name = 'ExchangeOnlineManagement'; Version = [version]'3.10.1'; ModuleBase = '/fake/ExchangeOnlineManagement/3.10.1' }
        } -ParameterFilter { $ListAvailable -and $Name -eq 'ExchangeOnlineManagement' }

        Mock Get-ConnectionInformation { $null }
        Mock Get-METAssemblyFileVersion { [version]'4.83.1.0' }
        Mock Connect-ExchangeOnline {}
    }

    Context 'A conflicting MSAL version is already loaded in-process' {
        It 'Throws an actionable error and never attempts Connect-ExchangeOnline' {
            Mock Test-METAssemblyLoadConflict {
                "A different version of Microsoft.Identity.Client (4.82.0.0, loaded from '/teams/Microsoft.Identity.Client.dll') is already active in this PowerShell session. Restart PowerShell, then run Connect-METSession again."
            }

            { Connect-METSession -SkipGraph -SkipTeams -UseDeviceAuthentication -ErrorAction Stop } |
                Should -Throw -ExpectedMessage '*Restart PowerShell*'

            Should -Invoke Connect-ExchangeOnline -Times 0 -Exactly
        }
    }

    Context 'No conflicting MSAL version is loaded' {
        It 'Proceeds to call Connect-ExchangeOnline' {
            Mock Test-METAssemblyLoadConflict { $null }

            Connect-METSession -SkipGraph -SkipTeams -UseDeviceAuthentication

            Should -Invoke Connect-ExchangeOnline -Times 1 -Exactly
        }
    }
}

Describe 'Connect-METSession connection ordering' {
    It 'Connects Exchange Online before Microsoft Graph' {
        # A List mutated via .Add() avoids the mock-scope assignment problem:
        # reference semantics mean no cross-scope variable assignment is needed.
        $order = [System.Collections.Generic.List[string]]::new()

        Mock Get-Module {
            [PSCustomObject]@{ Name = 'ExchangeOnlineManagement'; Version = [version]'3.10.1' }
        } -ParameterFilter { $ListAvailable -and $Name -eq 'ExchangeOnlineManagement' }

        Mock Get-Module {
            [PSCustomObject]@{ Name = $Name; Version = [version]'2.39.0' }
        } -ParameterFilter { $ListAvailable -and $Name -like 'Microsoft.Graph*' }

        Mock Get-MgContext { $null }
        Mock Get-ConnectionInformation { $null }
        Mock Connect-MgGraph { $order.Add('Graph') }
        Mock Connect-ExchangeOnline { $order.Add('ExchangeOnline') }

        Connect-METSession -SkipTeams -UseDeviceAuthentication

        $order.Count | Should -Be 2
        $order[0] | Should -Be 'ExchangeOnline'
        $order[1] | Should -Be 'Graph'
    }
}
