function Connect-METSession {
    [CmdletBinding(DefaultParameterSetName = 'Interactive')]
    param(
        [Parameter(ParameterSetName = 'Interactive')]
        [string] $UserPrincipalName,

        [Parameter(ParameterSetName = 'Interactive')]
        [switch] $DisableWAM,

        [Parameter(ParameterSetName = 'Interactive')]
        [switch] $UseDeviceAuthentication,

        [Parameter(ParameterSetName = 'ServicePrincipal', Mandatory)]
        [string] $AppId,

        [Parameter(ParameterSetName = 'ServicePrincipal', Mandatory)]
        [string] $TenantId,

        [Parameter(ParameterSetName = 'ServicePrincipal', Mandatory)]
        [string] $CertificateThumbprint,

        [Parameter(ParameterSetName = 'ManagedIdentity', Mandatory)]
        [switch] $ManagedIdentity,

        [Parameter()]
        [string] $DelegatedOrganization,

        [Parameter()]
        [switch] $SkipExchangeOnline,

        [Parameter()]
        [switch] $SkipGraph,

        [Parameter()]
        [switch] $SkipTeams
    )

    $graphScopes = @(
        'Policy.Read.All'
        'Organization.Read.All'
        'Group.Read.All'
        'User.Read.All'
    )

    # Exchange Online must connect first. Each module carries its own
    # Microsoft.Identity.Client (MSAL) build, only one of which can occupy the
    # default AssemblyLoadContext. ExchangeOnlineManagement ships the newest
    # (4.83.1 vs Graph's 4.82.1), and .NET resolves a lower version request
    # against a higher loaded one but never the reverse. Connecting Graph first
    # pins the older MSAL and Exchange then fails with 0x80131040. This only
    # protects against a conflict this function causes itself - if the caller's
    # session already loaded a conflicting MSAL build before ever calling
    # Connect-METSession (e.g. a prior Import-Module MicrosoftTeams/Graph/Az),
    # the check below surfaces that instead of the raw MSAL load failure.
    if (-not $SkipExchangeOnline) {
        $exoModule = Get-Module -ListAvailable -Name ExchangeOnlineManagement |
            Where-Object { $_.Version -ge [version]'3.0.0' } | Select-Object -First 1
        if (-not $exoModule) {
            throw "ExchangeOnlineManagement 3.x or later is not installed. Run: Install-Module ExchangeOnlineManagement -Scope CurrentUser"
        }

        $exoParams = @{
            ShowBanner            = $false
            ShowProgress          = $false
            SkipLoadingFormatData = $true
            SkipLoadingCmdletHelp = $true
        }

        if ($UserPrincipalName) {
            $exoParams['UserPrincipalName'] = $UserPrincipalName
        }

        if ($DisableWAM) {
            $exoParams['DisableWAM'] = $true
        }

        if ($UseDeviceAuthentication) {
            $exoParams['Device'] = $true
        }

        if ($DelegatedOrganization) {
            $exoParams['DelegatedOrganization'] = $DelegatedOrganization
        }

        switch ($PSCmdlet.ParameterSetName) {
            'ServicePrincipal' {
                $exoParams['AppId']                = $AppId
                $exoParams['Organization']          = $TenantId
                $exoParams['CertificateThumbprint'] = $CertificateThumbprint
            }
            'ManagedIdentity' {
                $exoParams['ManagedIdentity'] = $true
            }
        }

        $existing = Get-ConnectionInformation -ErrorAction SilentlyContinue |
            Where-Object { $_.State -eq 'Connected' } |
            Select-Object -First 1

        if (-not $existing) {
            # A different MSAL version already loaded in-process (e.g. from an
            # earlier Import-Module MicrosoftTeams/Graph/Az in this session) can
            # never be reconciled by connect order alone - .NET cannot unload or
            # replace an assembly once loaded. Detect that case up front so the
            # error names the real cause instead of surfacing MSAL's opaque
            # 0x80131040 manifest-mismatch failure.
            $requiredMsalVersion = $null
            if ($exoModule.ModuleBase) {
                $exoMsalPath = Join-Path $exoModule.ModuleBase 'netCore' 'Microsoft.Identity.Client.dll'
                $requiredMsalVersion = Get-METAssemblyFileVersion -Path $exoMsalPath
            }
            if ($requiredMsalVersion) {
                $conflict = Test-METAssemblyLoadConflict -AssemblyName 'Microsoft.Identity.Client' -RequiredVersion $requiredMsalVersion
                if ($conflict) {
                    throw "Failed to connect to Exchange Online: $conflict"
                }
            }

            try {
                Write-Verbose 'Connecting to Exchange Online...'
                Connect-ExchangeOnline @exoParams
            }
            catch {
                throw "Failed to connect to Exchange Online: $_`nOn Linux/macOS try: Connect-METSession -UseDeviceAuthentication -Verbose`nIf that still fails, try: Connect-METSession -DisableWAM -Verbose"
            }
        }
        else {
            Write-Verbose "Exchange Online already connected as $($existing.UserPrincipalName)."
        }
    }

    if (-not $SkipGraph) {
        $graphModuleMissing = @(
            'Microsoft.Graph.Identity.SignIns'
            'Microsoft.Graph.Groups'
        ) | Where-Object { -not (Get-Module -ListAvailable -Name $_ | Where-Object { $_.Version -ge [version]'2.0.0' }) }

        if ($graphModuleMissing) {
            Write-Warning "Optional Graph module(s) not installed: $($graphModuleMissing -join ', '). Group-membership expansion will fall back to Exchange Online cmdlets. Install with: Install-Module '$($graphModuleMissing[0])' -Scope CurrentUser"
        }
        else {
            $graphParams = @{ Scopes = $graphScopes; NoWelcome = $true }

            if ($UseDeviceAuthentication -and $PSCmdlet.ParameterSetName -eq 'Interactive') {
                $graphParams['UseDeviceCode'] = $true
            }

            switch ($PSCmdlet.ParameterSetName) {
                'ServicePrincipal' {
                    $graphParams = @{
                        ClientId              = $AppId
                        TenantId              = $TenantId
                        CertificateThumbprint = $CertificateThumbprint
                        NoWelcome             = $true
                    }
                }
                'ManagedIdentity' {
                    $graphParams = @{ Identity = $true; NoWelcome = $true }
                }
            }

            try {
                $mgContext = Get-MgContext -ErrorAction SilentlyContinue
                if (-not $mgContext) {
                    # A different MSAL version already loaded in-process (most often by
                    # ExchangeOnlineManagement connecting first, per the comment at the top
                    # of this function) cannot be reconciled by .NET at runtime. Detect it
                    # up front so the warning names the real cause instead of surfacing
                    # MSAL's opaque MissingMethodException/manifest-mismatch failure.
                    $graphAuthModule = Get-Module -ListAvailable -Name Microsoft.Graph.Authentication |
                        Sort-Object Version -Descending | Select-Object -First 1
                    $requiredMsalVersion = $null
                    if ($graphAuthModule.ModuleBase) {
                        $graphMsalPath = Join-Path $graphAuthModule.ModuleBase 'Dependencies' 'Core' 'Microsoft.Identity.Client.dll'
                        $requiredMsalVersion = Get-METAssemblyFileVersion -Path $graphMsalPath
                    }
                    if ($requiredMsalVersion) {
                        $conflict = Test-METAssemblyLoadConflict -AssemblyName 'Microsoft.Identity.Client' -RequiredVersion $requiredMsalVersion
                        if ($conflict) {
                            throw $conflict
                        }
                    }

                    Write-Verbose 'Connecting to Microsoft Graph...'
                    Connect-MgGraph @graphParams -ErrorAction Stop
                }
                else {
                    Write-Verbose "Microsoft Graph already connected as $($mgContext.Account)."
                }
            }
            catch {
                Write-Warning "Failed to connect to Microsoft Graph: $($_.Exception.Message) Group-membership expansion will fall back to Exchange Online cmdlets (reduced accuracy for Microsoft 365 Group references). Retry with: Connect-METSession -UseDeviceAuthentication"
            }
        }
    }

    if (-not $SkipTeams) {
        $teamsModule = Get-Module -ListAvailable -Name MicrosoftTeams |
            Where-Object { $_.Version -ge [version]'6.0.0' } | Select-Object -First 1
        if (-not $teamsModule) {
            Write-Warning 'MicrosoftTeams 6.x or later is not installed. Teams checks will be skipped. Install with: Install-Module MicrosoftTeams -Scope CurrentUser'
        }
        else {
            try {
                # Inside the try so an import failure (e.g. an MSAL assembly-load
                # conflict) degrades to a warning like every other Teams failure,
                # rather than aborting a session where EXO and Graph already connected.
                Import-Module MicrosoftTeams -ErrorAction Stop

                # Get-CsTenant throws (not returns $null) when not connected, so probe inside try/catch.
                $teamsConnection = $null
                try { $teamsConnection = Get-CsTenant -ErrorAction Stop } catch { $teamsConnection = $null }

                if (-not $teamsConnection) {
                    Write-Verbose 'Connecting to Microsoft Teams...'
                    $teamsParams = @{}
                    switch ($PSCmdlet.ParameterSetName) {
                        'Interactive' {
                            if ($UserPrincipalName) {
                                $teamsParams['AccountId'] = $UserPrincipalName
                            }
                            if ($UseDeviceAuthentication) {
                                $teamsParams['UseDeviceAuthentication'] = $true
                            }
                            # WAM became the default in MicrosoftTeams 7.9.0 and P/Invokes
                            # kernel32.dll, which does not exist off Windows. The switch is
                            # documented as temporary, so only pass it if it is still present.
                            $disableWamRequested = $DisableWAM -or -not $IsWindows
                            if ($disableWamRequested -and
                                (Get-Command Connect-MicrosoftTeams).Parameters.ContainsKey('DisableWAM')) {
                                $teamsParams['DisableWAM'] = $true
                            }
                        }
                        'ServicePrincipal' {
                            $teamsParams['ApplicationId'] = $AppId
                            $teamsParams['TenantId']      = $TenantId
                            $teamsParams['Certificate']   = Get-METCertificateByThumbprint -Thumbprint $CertificateThumbprint
                        }
                        'ManagedIdentity' {
                            $teamsParams['Identity'] = $true
                        }
                    }
                    Connect-MicrosoftTeams @teamsParams
                }
                else {
                    Write-Verbose "Microsoft Teams already connected to tenant $($teamsConnection.TenantId)."
                }
            }
            catch {
                $guidance = 'Teams checks will be skipped. Retry with: Connect-METSession -UseDeviceAuthentication'
                if ($_.Exception -is [System.DllNotFoundException]) {
                    $guidance = 'MicrosoftTeams 7.9.0+ defaults to WAM, which is Windows-only. ' +
                                'Retry with: Connect-METSession -UseDeviceAuthentication'
                }
                Write-Warning "Failed to connect to Microsoft Teams: $($_.Exception.Message) $guidance"
            }
        }
    }

    Write-Verbose 'MET session ready.'
}
