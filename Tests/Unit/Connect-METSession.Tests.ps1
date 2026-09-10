BeforeAll {
    $root = Join-Path $PSScriptRoot '..' '..'
    . "$root/Public/Connect-METSession.ps1"
    . "$root/Public/Disconnect-METSession.ps1"
    . "$root/Private/Get-METCertificateByThumbprint.ps1"
    . "$root/Private/Get-METCertificateFromFile.ps1"
    . "$root/Private/Get-METAssemblyFileVersion.ps1"
    . "$root/Private/Test-METAssemblyLoadConflict.ps1"
    . "$root/Private/Resolve-METTenantGuid.ps1"

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
            [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,
            [switch] $Identity
        )
    }

    function Disconnect-ExchangeOnline { [CmdletBinding(SupportsShouldProcess)] param() }
    function Disconnect-MgGraph { [CmdletBinding()] param() }
    function Disconnect-MicrosoftTeams { [CmdletBinding()] param() }

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
            [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,
            [string] $CertificateFilePath,
            [System.Security.SecureString] $CertificatePassword,
            [string] $CertificateThumbprint
        )
    }
}

Describe 'Connect-METSession Teams leg' {
    BeforeEach {
        $script:METConnection = $null
        $script:METSessionInfo = $null
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
        It 'Resolves the thumbprint to an X509Certificate2 and passes -Certificate' -Skip:(-not $IsWindows) {
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
            # -TenantId became mandatory in the ManagedIdentity set (Task 18, C-7) so
            # Connect-ExchangeOnline -ManagedIdentity -Organization can actually connect;
            # supplying it here does not change what this test asserts about Teams.
            Connect-METSession -SkipGraph -SkipExchangeOnline -ManagedIdentity -TenantId 'contoso.onmicrosoft.com'

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
        $script:METConnection = $null
        $script:METSessionInfo = $null
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
        $script:METConnection = $null
        $script:METSessionInfo = $null
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
    BeforeEach {
        $script:METConnection = $null
        $script:METSessionInfo = $null
    }

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

Describe 'Connect-METSession tenant-scoped session reuse - EXO' {
    BeforeEach {
        $script:METConnection = $null
        $script:METSessionInfo = $null
        Mock Get-Module {
            [PSCustomObject]@{ Name = 'ExchangeOnlineManagement'; Version = [version]'3.10.1'; ModuleBase = '/fake/ExchangeOnlineManagement/3.10.1' }
        } -ParameterFilter { $ListAvailable -and $Name -eq 'ExchangeOnlineManagement' }
        Mock Get-METAssemblyFileVersion { [version]'4.83.1.0' }
        Mock Test-METAssemblyLoadConflict { $null }
        Mock Connect-ExchangeOnline {}
    }

    Context 'Existing connection matches the requested delegated organization' {
        It 'Reuses the connection without reconnecting' {
            Mock Get-ConnectionInformation {
                [PSCustomObject]@{ State = 'Connected'; Organization = $null; DelegatedOrganization = 'customerb.onmicrosoft.com'; CertificateAuthentication = $false; UserPrincipalName = 'admin@msp.com' }
            }

            { Connect-METSession -SkipGraph -SkipTeams -DelegatedOrganization 'customerb.onmicrosoft.com' } | Should -Not -Throw
            Should -Invoke Connect-ExchangeOnline -Times 0 -Exactly
        }
    }

    Context 'Existing connection is for a different delegated organization' {
        It 'Throws naming the actually-connected org, and never calls Connect-ExchangeOnline' {
            Mock Get-ConnectionInformation {
                [PSCustomObject]@{ State = 'Connected'; Organization = $null; DelegatedOrganization = 'customera.onmicrosoft.com'; CertificateAuthentication = $false; UserPrincipalName = 'admin@msp.com' }
            }

            { Connect-METSession -SkipGraph -SkipTeams -DelegatedOrganization 'customerb.onmicrosoft.com' -ErrorAction Stop } |
                Should -Throw -ExpectedMessage '*customera.onmicrosoft.com*'

            Should -Invoke Connect-ExchangeOnline -Times 0 -Exactly
        }
    }

    Context 'Existing connection is interactive but ServicePrincipal was requested' {
        It 'Throws rather than silently reusing the interactive session' {
            Mock Get-ConnectionInformation {
                [PSCustomObject]@{ State = 'Connected'; Organization = 'contoso.onmicrosoft.com'; DelegatedOrganization = $null; CertificateAuthentication = $false; UserPrincipalName = 'admin@contoso.com' }
            }
            $fakeCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new()
            Mock Get-METCertificateFromFile { $fakeCert }
            $securePassword = New-Object System.Security.SecureString
            'p@ssw0rd'.ToCharArray() | ForEach-Object { $securePassword.AppendChar($_) }
            $certFile = Join-Path $TestDrive 'met-ci.pfx'
            New-Item -Path $certFile -ItemType File -Force | Out-Null

            { Connect-METSession -SkipGraph -SkipTeams `
                    -AppId '11111111-1111-1111-1111-111111111111' `
                    -TenantId 'contoso.onmicrosoft.com' `
                    -CertificatePath $certFile `
                    -CertificatePassword $securePassword `
                    -ErrorAction Stop } | Should -Throw -ExpectedMessage '*interactively*'

            Should -Invoke Connect-ExchangeOnline -Times 0 -Exactly
        }
    }

    Context 'No delegated organization or tenant was requested' {
        It 'Reuses any existing session without a mismatch check (unchanged default behavior)' {
            Mock Get-ConnectionInformation {
                [PSCustomObject]@{ State = 'Connected'; Organization = $null; DelegatedOrganization = $null; CertificateAuthentication = $false; UserPrincipalName = 'admin@somewhere.onmicrosoft.com' }
            }

            { Connect-METSession -SkipGraph -SkipTeams } | Should -Not -Throw
            Should -Invoke Connect-ExchangeOnline -Times 0 -Exactly
        }
    }

    Context 'Existing connection is Managed Identity and Managed Identity was requested again' {
        It 'Reuses the connection without throwing (Managed Identity is app-only but never certificate-based)' {
            Mock Get-ConnectionInformation {
                [PSCustomObject]@{ State = 'Connected'; Organization = $null; DelegatedOrganization = $null; CertificateAuthentication = $false; UserPrincipalName = $null }
            }

            # -TenantId became mandatory in the ManagedIdentity set (Task 18, C-7); supplying
            # it here does not change the reuse behavior this test asserts.
            { Connect-METSession -SkipGraph -SkipTeams -ManagedIdentity -TenantId 'contoso.onmicrosoft.com' -ErrorAction Stop } | Should -Not -Throw
            Should -Invoke Connect-ExchangeOnline -Times 0 -Exactly
        }
    }
}

Describe 'Connect-METSession tenant-scoped session reuse - Graph and Teams (ServicePrincipal)' {
    BeforeEach {
        $script:METConnection = $null
        $script:METSessionInfo = $null
        Mock Get-Module {
            [PSCustomObject]@{ Name = $Name; Version = [version]'2.39.0' }
        } -ParameterFilter { $ListAvailable -and $Name -like 'Microsoft.Graph*' }
        Mock Get-Module {
            [PSCustomObject]@{ Name = 'MicrosoftTeams'; Version = [version]'7.9.0' }
        } -ParameterFilter { $ListAvailable -and $Name -eq 'MicrosoftTeams' }
        Mock Import-Module {}
        Mock Connect-MgGraph {}
        Mock Connect-MicrosoftTeams {}
        $script:fakeCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new()
        Mock Get-METCertificateFromFile { $script:fakeCert }
        $script:securePassword = New-Object System.Security.SecureString
        'p@ssw0rd'.ToCharArray() | ForEach-Object { $script:securePassword.AppendChar($_) }
        $script:certFile = Join-Path $TestDrive 'met-ci.pfx'
        New-Item -Path $script:certFile -ItemType File -Force | Out-Null
    }

    Context 'Graph already connected to a different tenant' {
        It 'Throws naming the actually-connected tenant and never calls Connect-MgGraph' {
            Mock Get-MgContext { [PSCustomObject]@{ TenantId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'; Account = 'app@customerA' } }

            { Connect-METSession -SkipExchangeOnline -SkipTeams `
                    -AppId '11111111-1111-1111-1111-111111111111' `
                    -TenantId 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' `
                    -CertificatePath $script:certFile `
                    -CertificatePassword $script:securePassword `
                    -ErrorAction Stop } | Should -Throw -ExpectedMessage '*aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa*'

            Should -Invoke Connect-MgGraph -Times 0 -Exactly
        }
    }

    Context 'Teams already connected to a different tenant' {
        It 'Throws naming the actually-connected tenant and never calls Connect-MicrosoftTeams' {
            Mock Get-CsTenant { [PSCustomObject]@{ TenantId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' } }

            { Connect-METSession -SkipExchangeOnline -SkipGraph `
                    -AppId '11111111-1111-1111-1111-111111111111' `
                    -TenantId 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' `
                    -CertificatePath $script:certFile `
                    -CertificatePassword $script:securePassword `
                    -ErrorAction Stop } | Should -Throw -ExpectedMessage '*aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa*'

            Should -Invoke Connect-MicrosoftTeams -Times 0 -Exactly
        }
    }

    Context 'Graph already connected to the same tenant, requested via a domain name' {
        It 'Does not throw, since Resolve-METTenantGuid resolves the domain to the connected GUID' {
            Mock Get-MgContext { [PSCustomObject]@{ TenantId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'; Account = 'app@customerA' } }
            Mock Resolve-METTenantGuid { 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' } -ParameterFilter { $TenantId -eq 'contoso.onmicrosoft.com' }

            { Connect-METSession -SkipExchangeOnline -SkipTeams `
                    -AppId '11111111-1111-1111-1111-111111111111' `
                    -TenantId 'contoso.onmicrosoft.com' `
                    -CertificatePath $script:certFile `
                    -CertificatePassword $script:securePassword `
                    -ErrorAction Stop } | Should -Not -Throw

            Should -Invoke Connect-MgGraph -Times 0 -Exactly
        }
    }

    Context 'Graph already connected, but the requested tenant GUID cannot be resolved' {
        It 'Fails closed - throws instead of silently allowing reuse of an unverified session' {
            Mock Get-MgContext { [PSCustomObject]@{ TenantId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'; Account = 'app@customerA' } }
            Mock Resolve-METTenantGuid { $null } -ParameterFilter { $TenantId -eq 'contoso.onmicrosoft.com' }

            { Connect-METSession -SkipExchangeOnline -SkipTeams `
                    -AppId '11111111-1111-1111-1111-111111111111' `
                    -TenantId 'contoso.onmicrosoft.com' `
                    -CertificatePath $script:certFile `
                    -CertificatePassword $script:securePassword `
                    -ErrorAction Stop } | Should -Throw -ExpectedMessage '*could not be resolved*'

            Should -Invoke Connect-MgGraph -Times 0 -Exactly
        }
    }

    Context 'Teams already connected, but the requested tenant GUID cannot be resolved' {
        It 'Fails closed - throws instead of silently allowing reuse of an unverified session' {
            Mock Get-CsTenant { [PSCustomObject]@{ TenantId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' } }
            Mock Resolve-METTenantGuid { $null } -ParameterFilter { $TenantId -eq 'contoso.onmicrosoft.com' }

            { Connect-METSession -SkipExchangeOnline -SkipGraph `
                    -AppId '11111111-1111-1111-1111-111111111111' `
                    -TenantId 'contoso.onmicrosoft.com' `
                    -CertificatePath $script:certFile `
                    -CertificatePassword $script:securePassword `
                    -ErrorAction Stop } | Should -Throw -ExpectedMessage '*could not be resolved*'

            Should -Invoke Connect-MicrosoftTeams -Times 0 -Exactly
        }
    }
}

Describe 'Connect-METSession tenant-scoped session reuse - Graph and Teams (Interactive + DelegatedOrganization)' {
    BeforeEach {
        $script:METConnection = $null
        $script:METSessionInfo = $null
        Mock Get-Module {
            [PSCustomObject]@{ Name = $Name; Version = [version]'2.39.0' }
        } -ParameterFilter { $ListAvailable -and $Name -like 'Microsoft.Graph*' }
        Mock Get-Module {
            [PSCustomObject]@{ Name = 'MicrosoftTeams'; Version = [version]'7.9.0' }
        } -ParameterFilter { $ListAvailable -and $Name -eq 'MicrosoftTeams' }
        Mock Import-Module {}
        Mock Connect-MgGraph {}
        Mock Connect-MicrosoftTeams {}
    }

    Context 'Graph already connected to a stale delegated-org tenant, a different one requested' {
        It 'Throws instead of silently reusing the stale session (closes the MSSP cross-customer leak)' {
            Mock Get-MgContext { [PSCustomObject]@{ TenantId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'; Account = 'admin@msp.com' } }
            Mock Resolve-METTenantGuid { 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' } -ParameterFilter { $TenantId -eq 'customerb.onmicrosoft.com' }

            { Connect-METSession -SkipExchangeOnline -SkipTeams -DelegatedOrganization 'customerb.onmicrosoft.com' -ErrorAction Stop } |
                Should -Throw -ExpectedMessage '*aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa*'

            Should -Invoke Connect-MgGraph -Times 0 -Exactly
        }
    }

    Context 'Teams already connected to a stale delegated-org tenant, a different one requested' {
        It 'Throws instead of silently reusing the stale session (closes the MSSP cross-customer leak)' {
            Mock Get-CsTenant { [PSCustomObject]@{ TenantId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' } }
            Mock Resolve-METTenantGuid { 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' } -ParameterFilter { $TenantId -eq 'customerb.onmicrosoft.com' }

            { Connect-METSession -SkipExchangeOnline -SkipGraph -DelegatedOrganization 'customerb.onmicrosoft.com' -ErrorAction Stop } |
                Should -Throw -ExpectedMessage '*aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa*'

            Should -Invoke Connect-MicrosoftTeams -Times 0 -Exactly
        }
    }
}

Describe 'Connect-METSession Graph leg certificate load failure' {
    BeforeEach {
        $script:METConnection = $null
        $script:METSessionInfo = $null
        Mock Get-Module {
            [PSCustomObject]@{ Name = $Name; Version = [version]'2.39.0' }
        } -ParameterFilter { $ListAvailable -and $Name -like 'Microsoft.Graph*' }
        Mock Connect-MgGraph {}
        Mock Get-METCertificateFromFile { throw 'Bad password or corrupt PFX' }
    }

    Context '-CertificatePath fails to load for the ServicePrincipal Graph leg' {
        It 'Degrades to a warning instead of throwing uncaught and aborting the whole call' {
            $securePassword = New-Object System.Security.SecureString
            'p@ssw0rd'.ToCharArray() | ForEach-Object { $securePassword.AppendChar($_) }
            $certFile = Join-Path $TestDrive 'met-ci.pfx'
            New-Item -Path $certFile -ItemType File | Out-Null

            $script:graphWarnings = @()
            {
                $script:graphWarnings = @(
                    Connect-METSession -SkipExchangeOnline -SkipTeams `
                        -AppId '11111111-1111-1111-1111-111111111111' `
                        -TenantId 'contoso.onmicrosoft.com' `
                        -CertificatePath $certFile `
                        -CertificatePassword $securePassword `
                        -WarningAction Continue 3>&1
                )
            } | Should -Not -Throw

            ($script:graphWarnings -join ' ') | Should -Match 'Failed to connect to Microsoft Graph'
            Should -Invoke Connect-MgGraph -Times 0 -Exactly
        }
    }
}

Describe 'Connect-METSession cross-call identity guard' {
    BeforeEach {
        $script:METConnection = $null
        $script:METSessionInfo = $null
        Mock Get-Module {
            [PSCustomObject]@{ Name = 'ExchangeOnlineManagement'; Version = [version]'3.10.1'; ModuleBase = '/fake/ExchangeOnlineManagement/3.10.1' }
        } -ParameterFilter { $ListAvailable -and $Name -eq 'ExchangeOnlineManagement' }
        Mock Get-METAssemblyFileVersion { [version]'4.83.1.0' }
        Mock Test-METAssemblyLoadConflict { $null }
        Mock Get-ConnectionInformation { $null }
        Mock Connect-ExchangeOnline {}
    }

    Context 'A second call in the same process requests a different delegated organization' {
        It 'Throws before attempting to connect, without needing a live session to detect it' {
            Connect-METSession -SkipGraph -SkipTeams -DelegatedOrganization 'customera.onmicrosoft.com'
            Should -Invoke Connect-ExchangeOnline -Times 1 -Exactly

            { Connect-METSession -SkipGraph -SkipTeams -DelegatedOrganization 'customerb.onmicrosoft.com' -ErrorAction Stop } |
                Should -Throw -ExpectedMessage '*customera.onmicrosoft.com*'

            # Still only the one call from before the throw - the second attempt never got that far.
            Should -Invoke Connect-ExchangeOnline -Times 1 -Exactly
        }
    }

    Context 'A second call in the same process requests the same delegated organization' {
        It 'Does not throw' {
            Connect-METSession -SkipGraph -SkipTeams -DelegatedOrganization 'customera.onmicrosoft.com'
            { Connect-METSession -SkipGraph -SkipTeams -DelegatedOrganization 'customera.onmicrosoft.com' } | Should -Not -Throw
        }
    }

    Context 'After Disconnect-METSession, a different organization no longer throws' {
        It 'Clears the tracked identity' {
            Connect-METSession -SkipGraph -SkipTeams -DelegatedOrganization 'customera.onmicrosoft.com'
            Disconnect-METSession
            { Connect-METSession -SkipGraph -SkipTeams -DelegatedOrganization 'customerb.onmicrosoft.com' } | Should -Not -Throw
        }
    }
}

Describe 'Connect-METSession certificate file authentication' {
    BeforeEach {
        $script:METConnection = $null
        $script:METSessionInfo = $null
        Mock Get-Module {
            [PSCustomObject]@{ Name = 'ExchangeOnlineManagement'; Version = [version]'3.10.1'; ModuleBase = '/fake/ExchangeOnlineManagement/3.10.1' }
        } -ParameterFilter { $ListAvailable -and $Name -eq 'ExchangeOnlineManagement' }
        Mock Get-METAssemblyFileVersion { [version]'4.83.1.0' }
        Mock Test-METAssemblyLoadConflict { $null }
        Mock Get-ConnectionInformation { $null }
        Mock Connect-ExchangeOnline {}
        $script:fakeCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new()
        Mock Get-METCertificateFromFile { $script:fakeCert }
    }

    Context 'ServicePrincipal with -CertificatePath' {
        It 'Passes CertificateFilePath/CertificatePassword to Connect-ExchangeOnline, not a thumbprint' {
            $securePassword = New-Object System.Security.SecureString
            'p@ssw0rd'.ToCharArray() | ForEach-Object { $securePassword.AppendChar($_) }
            $certFile = Join-Path $TestDrive 'met-ci.pfx'
            New-Item -Path $certFile -ItemType File | Out-Null

            Connect-METSession -SkipGraph -SkipTeams `
                -AppId '11111111-1111-1111-1111-111111111111' `
                -TenantId 'contoso.onmicrosoft.com' `
                -CertificatePath $certFile `
                -CertificatePassword $securePassword

            Should -Invoke Connect-ExchangeOnline -Times 1 -Exactly -ParameterFilter {
                $CertificateFilePath -eq $certFile -and
                $null -ne $CertificatePassword -and
                -not $CertificateThumbprint
            }
        }
    }

    Context '-CertificatePath does not exist on disk' {
        It 'Throws before attempting any connection' {
            $securePassword = New-Object System.Security.SecureString
            'p@ssw0rd'.ToCharArray() | ForEach-Object { $securePassword.AppendChar($_) }

            { Connect-METSession -SkipGraph -SkipTeams `
                    -AppId '11111111-1111-1111-1111-111111111111' `
                    -TenantId 'contoso.onmicrosoft.com' `
                    -CertificatePath (Join-Path $TestDrive 'does-not-exist.pfx') `
                    -CertificatePassword $securePassword -ErrorAction Stop } | Should -Throw -ExpectedMessage '*does not exist*'

            Should -Invoke Connect-ExchangeOnline -Times 0 -Exactly
        }
    }

    Context 'Both -CertificateThumbprint and -CertificatePath supplied' {
        It 'Throws before attempting any connection' {
            $securePassword = New-Object System.Security.SecureString
            'p@ssw0rd'.ToCharArray() | ForEach-Object { $securePassword.AppendChar($_) }

            { Connect-METSession -SkipGraph -SkipTeams `
                    -AppId '11111111-1111-1111-1111-111111111111' `
                    -TenantId 'contoso.onmicrosoft.com' `
                    -CertificateThumbprint 'ABCDEF0123456789ABCDEF0123456789ABCDEF01' `
                    -CertificatePath '/certs/met-ci.pfx' `
                    -CertificatePassword $securePassword -ErrorAction Stop } | Should -Throw -ExpectedMessage '*not both*'

            Should -Invoke Connect-ExchangeOnline -Times 0 -Exactly
        }
    }

    Context 'Neither -CertificateThumbprint nor -CertificatePath supplied' {
        It 'Throws before attempting any connection' {
            { Connect-METSession -SkipGraph -SkipTeams `
                    -AppId '11111111-1111-1111-1111-111111111111' `
                    -TenantId 'contoso.onmicrosoft.com' -ErrorAction Stop } | Should -Throw -ExpectedMessage '*CertificateThumbprint*'

            Should -Invoke Connect-ExchangeOnline -Times 0 -Exactly
        }
    }

    Context '-CertificatePath without -CertificatePassword' {
        It 'Throws before attempting any connection' {
            { Connect-METSession -SkipGraph -SkipTeams `
                    -AppId '11111111-1111-1111-1111-111111111111' `
                    -TenantId 'contoso.onmicrosoft.com' `
                    -CertificatePath '/certs/met-ci.pfx' -ErrorAction Stop } | Should -Throw -ExpectedMessage '*CertificatePassword*'

            Should -Invoke Connect-ExchangeOnline -Times 0 -Exactly
        }
    }

    Context '-TenantId is a GUID while Exchange Online is being connected' {
        It 'Throws before attempting any connection, naming the primary domain requirement' {
            $securePassword = New-Object System.Security.SecureString
            'p@ssw0rd'.ToCharArray() | ForEach-Object { $securePassword.AppendChar($_) }
            $certFile = Join-Path $TestDrive 'met-ci.pfx'
            New-Item -Path $certFile -ItemType File -Force | Out-Null

            { Connect-METSession -SkipGraph -SkipTeams `
                    -AppId '11111111-1111-1111-1111-111111111111' `
                    -TenantId 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' `
                    -CertificatePath $certFile -CertificatePassword $securePassword -ErrorAction Stop } |
                Should -Throw -ExpectedMessage '*.onmicrosoft.com*'

            Should -Invoke Connect-ExchangeOnline -Times 0 -Exactly
        }
    }

    Context '-TenantId is a GUID but -SkipExchangeOnline is set' {
        It 'Does not throw, since Graph/Teams accept a GUID tenant ID' {
            $securePassword = New-Object System.Security.SecureString
            'p@ssw0rd'.ToCharArray() | ForEach-Object { $securePassword.AppendChar($_) }
            $certFile = Join-Path $TestDrive 'met-ci.pfx'
            New-Item -Path $certFile -ItemType File -Force | Out-Null

            { Connect-METSession -SkipExchangeOnline -SkipGraph -SkipTeams `
                    -AppId '11111111-1111-1111-1111-111111111111' `
                    -TenantId 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' `
                    -CertificatePath $certFile -CertificatePassword $securePassword -ErrorAction Stop } | Should -Not -Throw
        }
    }
}

Describe 'Connect-METSession device-code warning' {
    BeforeEach {
        $script:METConnection = $null
        $script:METSessionInfo = $null
        Mock Get-Module {
            [PSCustomObject]@{ Name = 'ExchangeOnlineManagement'; Version = [version]'3.10.1'; ModuleBase = '/fake/ExchangeOnlineManagement/3.10.1' }
        } -ParameterFilter { $ListAvailable -and $Name -eq 'ExchangeOnlineManagement' }
        Mock Get-METAssemblyFileVersion { [version]'4.83.1.0' }
        Mock Test-METAssemblyLoadConflict { $null }
        Mock Get-ConnectionInformation { $null }
        Mock Connect-ExchangeOnline {}
    }

    It 'Warns that device code is a phishing vector whenever -UseDeviceAuthentication is used' {
        $warnings = @(Connect-METSession -SkipGraph -SkipTeams -UseDeviceAuthentication -WarningAction Continue 3>&1)
        ($warnings -join ' ') | Should -Match 'phishing'
    }

    It 'Does not warn when -UseDeviceAuthentication is not used' {
        $warnings = @(Connect-METSession -SkipGraph -SkipTeams -WarningAction Continue 3>&1)
        ($warnings -join ' ') | Should -Not -Match 'phishing'
    }
}

Describe 'Connect-METSession threads -DelegatedOrganization to Graph and Teams' {
    BeforeEach {
        $script:METConnection = $null
        $script:METSessionInfo = $null
        Mock Get-Module {
            [PSCustomObject]@{ Name = $Name; Version = [version]'2.39.0' }
        } -ParameterFilter { $ListAvailable -and $Name -like 'Microsoft.Graph*' }
        Mock Get-Module {
            [PSCustomObject]@{ Name = 'MicrosoftTeams'; Version = [version]'7.9.0' }
        } -ParameterFilter { $ListAvailable -and $Name -eq 'MicrosoftTeams' }
        Mock Import-Module {}
        Mock Get-MgContext { $null }
        Mock Get-CsTenant { throw [System.UnauthorizedAccessException]::new('Session is not established') }
        Mock Connect-MgGraph {}
        Mock Connect-MicrosoftTeams {}
    }

    It 'Passes -DelegatedOrganization as -TenantId to Connect-MgGraph (Interactive)' {
        Connect-METSession -SkipExchangeOnline -DelegatedOrganization 'customerb.onmicrosoft.com'

        Should -Invoke Connect-MgGraph -Times 1 -Exactly -ParameterFilter {
            $TenantId -eq 'customerb.onmicrosoft.com'
        }
    }

    It 'Passes -DelegatedOrganization as -TenantId to Connect-MicrosoftTeams (Interactive)' {
        Connect-METSession -SkipExchangeOnline -DelegatedOrganization 'customerb.onmicrosoft.com'

        Should -Invoke Connect-MicrosoftTeams -Times 1 -Exactly -ParameterFilter {
            $TenantId -eq 'customerb.onmicrosoft.com'
        }
    }
}

Describe 'Connect-METSession session info tracking' {
    BeforeEach {
        $script:METConnection = $null
        $script:METSessionInfo = $null
        Mock Get-Module {
            [PSCustomObject]@{ Name = 'ExchangeOnlineManagement'; Version = [version]'3.10.1'; ModuleBase = '/fake/ExchangeOnlineManagement/3.10.1' }
        } -ParameterFilter { $ListAvailable -and $Name -eq 'ExchangeOnlineManagement' }
        Mock Get-METAssemblyFileVersion { [version]'4.83.1.0' }
        Mock Test-METAssemblyLoadConflict { $null }
        Mock Get-ConnectionInformation { $null }
        Mock Connect-ExchangeOnline {}
    }

    It 'Records auth mode, tenant identity, device-code usage, and connected services after a successful connect' {
        Connect-METSession -SkipGraph -SkipTeams -DelegatedOrganization 'customerb.onmicrosoft.com' -UseDeviceAuthentication -WarningAction SilentlyContinue

        $script:METSessionInfo.AuthMode | Should -Be 'Interactive'
        $script:METSessionInfo.TenantIdentity | Should -Be 'customerb.onmicrosoft.com'
        $script:METSessionInfo.DeviceCodeUsed | Should -BeTrue
        $script:METSessionInfo.ServicesConnected | Should -Contain 'ExchangeOnline'
    }
}

Describe 'Disconnect-METSession' {
    BeforeEach {
        $script:METConnection = $null
        $script:METSessionInfo = $null
    }

    It 'Disconnects each leg independently and one failure does not block the others' {
        Mock Get-ConnectionInformation { [PSCustomObject]@{ State = 'Connected' } }
        Mock Disconnect-ExchangeOnline { throw 'already gone' }
        Mock Get-MgContext { [PSCustomObject]@{ Account = 'admin@contoso.com' } }
        Mock Disconnect-MgGraph {}
        Mock Get-CsTenant { [PSCustomObject]@{ TenantId = '00000000-0000-0000-0000-000000000000' } }
        Mock Disconnect-MicrosoftTeams {}

        $warnings = @(Disconnect-METSession -WarningAction Continue 3>&1)

        Should -Invoke Disconnect-MgGraph -Times 1 -Exactly
        Should -Invoke Disconnect-MicrosoftTeams -Times 1 -Exactly
        ($warnings -join ' ') | Should -Match 'already gone'
    }

    It 'Skips a leg that is not connected rather than erroring' {
        Mock Get-ConnectionInformation { $null }
        Mock Disconnect-ExchangeOnline {}
        Mock Get-MgContext { $null }
        Mock Disconnect-MgGraph {}
        Mock Get-CsTenant { throw [System.Management.Automation.CommandNotFoundException]::new('Get-CsTenant is not recognized') }
        Mock Disconnect-MicrosoftTeams {}

        { Disconnect-METSession } | Should -Not -Throw
        Should -Invoke Disconnect-ExchangeOnline -Times 0 -Exactly
        Should -Invoke Disconnect-MicrosoftTeams -Times 0 -Exactly
    }

    It 'Leaves the tracked identity in place when a leg fails to disconnect, so a later Connect-METSession to a different org is still blocked' {
        $script:METConnection = @{ Mode = 'Interactive'; Org = 'customera.onmicrosoft.com' }
        $script:METSessionInfo = [PSCustomObject]@{ AuthMode = 'Interactive' }

        Mock Get-ConnectionInformation { [PSCustomObject]@{ State = 'Connected' } }
        Mock Disconnect-ExchangeOnline {}
        Mock Get-MgContext { [PSCustomObject]@{ Account = 'admin@customera.onmicrosoft.com' } }
        Mock Disconnect-MgGraph { throw 'stuck session' }
        Mock Get-CsTenant { throw [System.Management.Automation.CommandNotFoundException]::new('Get-CsTenant is not recognized') }
        Mock Disconnect-MicrosoftTeams {}

        Disconnect-METSession -WarningAction SilentlyContinue

        $script:METConnection | Should -Not -BeNullOrEmpty
        $script:METConnection.Org | Should -Be 'customera.onmicrosoft.com'
        $script:METSessionInfo | Should -Not -BeNullOrEmpty
    }

    It 'Clears the tracked identity once every leg disconnects cleanly' {
        $script:METConnection = @{ Mode = 'Interactive'; Org = 'customera.onmicrosoft.com' }
        $script:METSessionInfo = [PSCustomObject]@{ AuthMode = 'Interactive' }

        Mock Get-ConnectionInformation { $null }
        Mock Get-MgContext { $null }
        Mock Get-CsTenant { throw [System.Management.Automation.CommandNotFoundException]::new('Get-CsTenant is not recognized') }

        Disconnect-METSession

        $script:METConnection | Should -BeNullOrEmpty
        $script:METSessionInfo | Should -BeNullOrEmpty
    }

    It 'Treats an ambiguous Get-CsTenant probe failure as an indeterminate disconnect (not "not connected"), keeping tracking in place' {
        $script:METConnection = @{ Mode = 'Interactive'; Org = 'customera.onmicrosoft.com' }
        $script:METSessionInfo = [PSCustomObject]@{ AuthMode = 'Interactive' }

        Mock Get-ConnectionInformation { $null }
        Mock Get-MgContext { $null }
        Mock Get-CsTenant { throw 'Service temporarily unavailable' }
        Mock Disconnect-MicrosoftTeams {}

        $warnings = @(Disconnect-METSession -WarningAction Continue 3>&1)

        Should -Invoke Disconnect-MicrosoftTeams -Times 0 -Exactly
        ($warnings -join ' ') | Should -Match 'Microsoft Teams'
        $script:METConnection | Should -Not -BeNullOrEmpty
        $script:METSessionInfo | Should -Not -BeNullOrEmpty
    }
}

Describe 'Connect-METSession concurrent session verification' {
    BeforeEach {
        $script:METConnection = $null
        $script:METSessionInfo = $null
        Mock Get-Module {
            [PSCustomObject]@{ Name = 'ExchangeOnlineManagement'; Version = [version]'3.10.1'; ModuleBase = '/fake/ExchangeOnlineManagement/3.10.1' }
        } -ParameterFilter { $ListAvailable -and $Name -eq 'ExchangeOnlineManagement' }
        Mock Get-METAssemblyFileVersion { [version]'4.83.1.0' }
        Mock Test-METAssemblyLoadConflict { $null }
        Mock Connect-ExchangeOnline {}
    }

    Context 'Two connected sessions belonging to different organizations' {
        It 'Refuses to reuse, naming both organizations' {
            Mock Get-ConnectionInformation {
                @(
                    [PSCustomObject]@{ State = 'Connected'; Organization = 'customer-a.onmicrosoft.com'; DelegatedOrganization = $null; UserPrincipalName = 'ops@mssp.com' }
                    [PSCustomObject]@{ State = 'Connected'; Organization = 'customer-b.onmicrosoft.com'; DelegatedOrganization = $null; UserPrincipalName = 'ops@mssp.com' }
                )
            }

            { Connect-METSession -DelegatedOrganization 'customer-a.onmicrosoft.com' -SkipGraph -SkipTeams -ErrorAction Stop } |
                Should -Throw -ExpectedMessage '*customer-a.onmicrosoft.com*customer-b.onmicrosoft.com*'

            Should -Invoke Connect-ExchangeOnline -Times 0 -Exactly
        }
    }

    Context 'Two connected sessions for the same matching organization' {
        It 'Reuses without reconnecting' {
            Mock Get-ConnectionInformation {
                @(
                    [PSCustomObject]@{ State = 'Connected'; Organization = 'customer-a.onmicrosoft.com'; DelegatedOrganization = $null; UserPrincipalName = 'ops@mssp.com' }
                    [PSCustomObject]@{ State = 'Connected'; Organization = 'customer-a.onmicrosoft.com'; DelegatedOrganization = $null; UserPrincipalName = 'ops@mssp.com' }
                )
            }

            { Connect-METSession -DelegatedOrganization 'customer-a.onmicrosoft.com' -SkipGraph -SkipTeams -ErrorAction Stop } | Should -Not -Throw
            Should -Invoke Connect-ExchangeOnline -Times 0 -Exactly
        }
    }

    Context 'The requested org matches the second session but not the first' {
        It 'Still refuses - a matching session elsewhere in the list is not sufficient' {
            Mock Get-ConnectionInformation {
                @(
                    [PSCustomObject]@{ State = 'Connected'; Organization = 'customer-b.onmicrosoft.com'; DelegatedOrganization = $null; UserPrincipalName = 'ops@mssp.com' }
                    [PSCustomObject]@{ State = 'Connected'; Organization = 'customer-a.onmicrosoft.com'; DelegatedOrganization = $null; UserPrincipalName = 'ops@mssp.com' }
                )
            }

            { Connect-METSession -DelegatedOrganization 'customer-a.onmicrosoft.com' -SkipGraph -SkipTeams -ErrorAction Stop } |
                Should -Throw -ExpectedMessage '*customer-b.onmicrosoft.com*'

            Should -Invoke Connect-ExchangeOnline -Times 0 -Exactly
        }
    }
}

Describe 'Connect-METSession certificate thumbprint platform guard' {
    # Produced 'A parameter cannot be found that matches parameter name
    # CertificateThumbprint' deep inside Connect-ExchangeOnline, then suggested
    # -UseDeviceAuthentication and -DisableWAM - both irrelevant to a service
    # principal certificate problem, and one is the phishing vector the module works
    # elsewhere to de-emphasise.
    It 'throws before connecting when -CertificateThumbprint is used off Windows' -Skip:($IsWindows) {
        { Connect-METSession -AppId '00000000-0000-0000-0000-000000000001' `
              -TenantId 'contoso.onmicrosoft.com' -CertificateThumbprint 'ABCD1234' } |
            Should -Throw -ExpectedMessage '*Windows-only*'
    }

    It 'points at -CertificatePath in the message' -Skip:($IsWindows) {
        $caught = $null
        try {
            Connect-METSession -AppId '00000000-0000-0000-0000-000000000001' `
                -TenantId 'contoso.onmicrosoft.com' -CertificateThumbprint 'ABCD1234'
        } catch { $caught = $_ }

        $caught.Exception.Message | Should -Match '-CertificatePath'
        $caught.Exception.Message | Should -Not -Match 'UseDeviceAuthentication'
    }
}

Describe 'Connect-METSession -DisableWAM parameter sets' {
    # The rest of this file dot-sources Public/Private scripts directly rather than
    # importing the packaged module (see MET.Module.Tests.ps1's header comment), so the
    # real MET module is not otherwise loaded in this session. These two Describe blocks
    # need it for -Module/-InModuleScope introspection, so import it here.
    BeforeAll {
        # This file dot-sources Connect-METSession.ps1 directly (see the top BeforeAll),
        # which defines a same-named function ahead of the module import below. Left in
        # place, that shadow breaks Get-Command/-Module resolution for the module's own
        # copy, so it has to go before the real module is loaded.
        Remove-Item -Path 'Function:\Connect-METSession' -ErrorAction SilentlyContinue
        $script:ManifestPath = Join-Path $PSScriptRoot '..' '..' 'MET.psd1'
        Import-Module $script:ManifestPath -Force -ErrorAction Stop
    }

    # README presents -DisableWAM as a general remedy, but it was declared only in the
    # Interactive set, so combining it with -AppId failed with 'Parameter set cannot be
    # resolved' - naming no parameter at all.
    It 'is valid in every parameter set' {
        $parameter = (Get-Command -Name 'Connect-METSession' -Module 'MET').Parameters['DisableWAM']
        $sets = $parameter.Attributes |
            Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
            ForEach-Object { $_.ParameterSetName }

        $sets | Should -Contain '__AllParameterSets'
    }

    It 'keeps -UseDeviceAuthentication scoped to Interactive' {
        $parameter = (Get-Command -Name 'Connect-METSession' -Module 'MET').Parameters['UseDeviceAuthentication']
        $sets = $parameter.Attributes |
            Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
            ForEach-Object { $_.ParameterSetName }

        $sets | Should -Contain 'Interactive'
        $sets | Should -Not -Contain '__AllParameterSets'
    }
}

Describe 'Connect-METSession -DisableWAM capability probe (C-22)' {
    BeforeAll {
        # This file dot-sources Connect-METSession.ps1 directly (see the top BeforeAll),
        # which defines a same-named function ahead of the module import below. Left in
        # place, that shadow breaks Get-Command/-Module resolution for the module's own
        # copy, so it has to go before the real module is loaded.
        Remove-Item -Path 'Function:\Connect-METSession' -ErrorAction SilentlyContinue
        $script:ManifestPath = Join-Path $PSScriptRoot '..' '..' 'MET.psd1'
        Import-Module $script:ManifestPath -Force -ErrorAction Stop
    }

    # WAM became the EXO default broker in 3.7.0, but -DisableWAM shipped in 3.7.2, so on
    # 3.0-3.6 passing it produces a raw parameter binding error. The Teams leg already
    # probes for exactly this at :462-465; the EXO leg did not.
    It 'reports false when the parameter is not declared' {
        InModuleScope 'MET' {
            Mock -CommandName 'Get-Command' -MockWith {
                [PSCustomObject]@{ Parameters = @{} }
            } -ParameterFilter { $Name -eq 'Connect-ExchangeOnline' }

            Test-METExoSupportsDisableWam | Should -BeFalse
        }
    }

    It 'reports true when the parameter is declared' {
        InModuleScope 'MET' {
            Mock -CommandName 'Get-Command' -MockWith {
                [PSCustomObject]@{ Parameters = @{ 'DisableWAM' = $true } }
            } -ParameterFilter { $Name -eq 'Connect-ExchangeOnline' }

            Test-METExoSupportsDisableWam | Should -BeTrue
        }
    }

    It 'reports false when Connect-ExchangeOnline is not present at all' {
        InModuleScope 'MET' {
            Mock -CommandName 'Get-Command' -MockWith { $null } `
                -ParameterFilter { $Name -eq 'Connect-ExchangeOnline' }

            Test-METExoSupportsDisableWam | Should -BeFalse
        }
    }
}

Describe 'Connect-METSession managed identity parameters' {
    # This file dot-sources Connect-METSession.ps1 directly (see the top BeforeAll),
    # which defines a same-named function ahead of the module import below. Left in
    # place, that shadow breaks Get-Command/-Module resolution for the module's own
    # copy, so it has to go before the real module is loaded - same as the two
    # -DisableWAM Describe blocks above.
    BeforeAll {
        Remove-Item -Path 'Function:\Connect-METSession' -ErrorAction SilentlyContinue
        $script:ManifestPath = Join-Path $PSScriptRoot '..' '..' 'MET.psd1'
        Import-Module $script:ManifestPath -Force -ErrorAction Stop
    }

    # Microsoft documents Connect-ExchangeOnline -ManagedIdentity -Organization
    # <domain>.onmicrosoft.com as required. -Organization was only ever set in the
    # ServicePrincipal branch, and the MI set had no -TenantId, so with EXO failure
    # fatal the whole parameter set aborted.
    It 'accepts -TenantId in the ManagedIdentity set' {
        $parameter = (Get-Command -Name 'Connect-METSession' -Module 'MET').Parameters['TenantId']
        $sets = $parameter.Attributes |
            Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
            ForEach-Object { $_.ParameterSetName }

        $sets | Should -Contain 'ManagedIdentity'
    }

    It 'requires -TenantId in the ManagedIdentity set' {
        $parameter = (Get-Command -Name 'Connect-METSession' -Module 'MET').Parameters['TenantId']
        $mandatory = $parameter.Attributes |
            Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] -and
                           $_.ParameterSetName -eq 'ManagedIdentity' } |
            ForEach-Object { $_.Mandatory }

        $mandatory | Should -Contain $true
    }

    It 'exposes -ManagedIdentityAccountId for user-assigned identities' {
        (Get-Command -Name 'Connect-METSession' -Module 'MET').Parameters.Keys |
            Should -Contain 'ManagedIdentityAccountId'
    }

    It 'rejects a GUID -TenantId for managed identity, as it does for app-only' {
        { Connect-METSession -ManagedIdentity `
              -TenantId '00000000-0000-0000-0000-000000000001' } |
            Should -Throw -ExpectedMessage '*onmicrosoft.com*'
    }
}
