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

        # Must be the tenant's primary .onmicrosoft.com domain name, not the tenant GUID, when
        # connecting Exchange Online - Connect-ExchangeOnline's -Organization parameter for
        # app-only authentication rejects GUIDs outright. Graph and Teams accept either form.
        [Parameter(ParameterSetName = 'ServicePrincipal', Mandatory)]
        [string] $TenantId,

        [Parameter(ParameterSetName = 'ServicePrincipal')]
        [string] $CertificateThumbprint,

        [Parameter(ParameterSetName = 'ServicePrincipal')]
        [string] $CertificatePath,

        [Parameter(ParameterSetName = 'ServicePrincipal')]
        [System.Security.SecureString] $CertificatePassword,

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

    if ($PSCmdlet.ParameterSetName -eq 'ServicePrincipal') {
        if ($CertificateThumbprint -and $CertificatePath) {
            throw 'Specify either -CertificateThumbprint or -CertificatePath, not both.'
        }
        if (-not $CertificateThumbprint -and -not $CertificatePath) {
            throw 'ServicePrincipal authentication requires either -CertificateThumbprint (Windows certificate store) or -CertificatePath (works on any platform, including Linux/macOS/Codespaces).'
        }
        if ($CertificatePath -and -not $CertificatePassword) {
            throw '-CertificatePath requires -CertificatePassword.'
        }
        if ($CertificatePath) {
            # Connect-ExchangeOnline's own CertificateFilePath validation calls the raw .NET
            # File.Exists() on this string, which - unlike PowerShell's own path cmdlets - never
            # expands '~' or resolves a relative path. Left alone, a path like '~/cert.pfx' fails
            # with the generic, misleading "Certificate is not accessible to the current user."
            # Resolving to an absolute path once here fixes it for the EXO, Graph, and Teams legs.
            $resolvedCertPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($CertificatePath)
            if (-not (Test-Path -LiteralPath $resolvedCertPath -PathType Leaf)) {
                throw "-CertificatePath '$CertificatePath' does not exist (resolved to '$resolvedCertPath')."
            }
            $CertificatePath = $resolvedCertPath
        }
        if (-not $SkipExchangeOnline -and $TenantId -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
            throw "-TenantId must be the tenant's primary .onmicrosoft.com domain name (e.g. 'contoso.onmicrosoft.com'), not the tenant GUID - Connect-ExchangeOnline's -Organization parameter for app-only authentication rejects GUIDs. Find it in the Entra admin center under Overview > 'Primary domain', or pass -SkipExchangeOnline if you only need Graph/Teams."
        }
    }

    # Storm-2372 and follow-on campaigns (Microsoft Security Blog, Feb 2025 - Apr 2026) abuse the
    # device-code flow's legitimate UX: an attacker generates a real device code and social-engineers
    # a victim into entering it, handing over a fully-authenticated session with no credential theft
    # or MFA bypass needed. Microsoft's own current guidance: "block device code flow wherever
    # possible... allow only where necessary." See docs/gap-analysis-2026-08-connect-session-security.md.
    if ($UseDeviceAuthentication) {
        Write-Warning 'Device code authentication requested (-UseDeviceAuthentication). This flow is a documented phishing vector (Microsoft: "block wherever possible, allow only where necessary") - use it only when no browser is reachable at all (a true headless host). Prefer -DisableWAM on an interactive host, or -CertificatePath for unattended/CI use.'
    }

    $requestedMode = $PSCmdlet.ParameterSetName
    $requestedOrg = switch ($requestedMode) {
        'ServicePrincipal' { $TenantId }
        default            { if ($DelegatedOrganization) { $DelegatedOrganization } else { $null } }
    }

    # Cross-call guard within the same PowerShell process: if a prior Connect-METSession call in
    # this session already established a different identity, later legs below may reuse EXO/Graph/
    # Teams connections that Connect-METSession itself doesn't have independent proof are wrong-tenant
    # (this is the only reliable check available for Graph/Teams in Interactive+DelegatedOrganization
    # mode, since neither SDK's returned context exposes the domain name originally requested - only
    # a resolved tenant GUID). EXO gets a second, fully independent check below regardless.
    if ($script:METConnection -and ($requestedMode -ne $script:METConnection.Mode -or
            ($requestedOrg -and $script:METConnection.Org -and $requestedOrg -ne $script:METConnection.Org))) {
        $previousIdentity = if ($script:METConnection.Org) { $script:METConnection.Org } else { $script:METConnection.Mode }
        $newIdentity = if ($requestedOrg) { $requestedOrg } else { $requestedMode }
        throw "Connect-METSession already established a session in this PowerShell process for '$previousIdentity'. Requesting '$newIdentity' now would reuse that connection's Exchange Online/Graph/Teams sessions without actually switching tenant or auth mode. Run Disconnect-METSession first, then reconnect to the new organization."
    }

    # User.Read.All is deliberately not requested: the only Graph call sites are
    # Expand-METGroupMembership.ps1 (Get-MgGroup/Get-MgGroupTransitiveMember, covered by
    # Group.Read.All) and MET-Teams014 (Get-MgPolicyCrossTenantAccessPolicyDefault/
    # Get-MgPolicyAuthorizationPolicy, covered by Policy.Read.All) - neither needs it, and
    # least-privilege scoping matters for an interactive admin consent prompt.
    $graphScopes = @(
        'Policy.Read.All'
        'Organization.Read.All'
        'Group.Read.All'
    )

    $servicesConnected = [System.Collections.Generic.List[string]]::new()

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
                $exoParams['AppId']       = $AppId
                $exoParams['Organization'] = $TenantId
                if ($CertificatePath) {
                    $exoParams['CertificateFilePath'] = $CertificatePath
                    $exoParams['CertificatePassword'] = $CertificatePassword
                }
                else {
                    $exoParams['CertificateThumbprint'] = $CertificateThumbprint
                }
            }
            'ManagedIdentity' {
                $exoParams['ManagedIdentity'] = $true
            }
        }

        $existing = Get-ConnectionInformation -ErrorAction SilentlyContinue |
            Where-Object { $_.State -eq 'Connected' } |
            Select-Object -First 1

        if ($existing) {
            # Reusing a live connection without checking whose tenant it belongs to is a
            # cross-customer data leak for -DelegatedOrganization/MSSP usage: run against
            # customer A, forget to disconnect, run against customer B - the report gets
            # labeled B but reads A's actual configuration. Organization/DelegatedOrganization
            # directly reflect what Connect-ExchangeOnline was told to connect to, regardless
            # of which one applies for this auth mode, so checking both covers every case.
            if ($requestedOrg -and $existing.Organization -ne $requestedOrg -and $existing.DelegatedOrganization -ne $requestedOrg) {
                $existingOrg = if ($existing.DelegatedOrganization) { $existing.DelegatedOrganization } else { $existing.Organization }
                throw "Exchange Online is already connected to '$existingOrg' (as $($existing.UserPrincipalName)), not the requested organization '$requestedOrg'. Run Disconnect-METSession first, then reconnect to the correct organization."
            }
            # CertificateAuthentication is only ever set for CBA connections (Microsoft's own
            # Get-ConnectionInformation docs: "the AppId parameter ... for CBA connections"), so it
            # can't distinguish interactive from Managed Identity - both are app-only, but only one
            # is certificate-based. UserPrincipalName is populated for every interactive sign-in and
            # never for an app-only session (CBA or Managed Identity alike), so it works for both.
            if ($PSCmdlet.ParameterSetName -in @('ServicePrincipal', 'ManagedIdentity') -and $existing.UserPrincipalName) {
                throw "Exchange Online is already connected interactively (as $($existing.UserPrincipalName)), not via app-only authentication. Run Disconnect-METSession first, then reconnect with -CertificateThumbprint/-CertificatePath or -ManagedIdentity."
            }
        }

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
                $servicesConnected.Add('ExchangeOnline')
            }
            catch {
                $onWindowsRetry = if ($IsWindows) { "On Windows try: Connect-METSession -DisableWAM -UserPrincipalName <upn> -Verbose" }
                                   else { "On a headless host with no reachable browser try: Connect-METSession -UseDeviceAuthentication -Verbose`nOtherwise try: Connect-METSession -DisableWAM -Verbose" }
                throw "Failed to connect to Exchange Online: $_`n$onWindowsRetry"
            }
        }
        else {
            $servicesConnected.Add('ExchangeOnline')
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

            if ($DelegatedOrganization -and $PSCmdlet.ParameterSetName -eq 'Interactive') {
                # Connect-MgGraph's UserParameterSet accepts -TenantId for exactly this
                # (CSP/GDAP delegated-admin) scenario - previously this was silently ignored
                # for Graph, so a delegated-org run could authenticate against the operator's
                # own home tenant instead of the customer's.
                $graphParams['TenantId'] = $DelegatedOrganization
            }

            # Certificate loading happens before the try/catch below so it must be guarded
            # separately - otherwise a bad -CertificatePath/-CertificatePassword throws
            # uncaught and aborts the whole Connect-METSession call (including the Teams leg,
            # which runs after this one), contradicting the "a failed Graph connection is
            # non-fatal" design every other failure path here follows.
            $graphCertLoadError = $null
            switch ($PSCmdlet.ParameterSetName) {
                'ServicePrincipal' {
                    $graphParams = @{
                        ClientId  = $AppId
                        TenantId  = $TenantId
                        NoWelcome = $true
                    }
                    if ($CertificatePath) {
                        try {
                            $graphParams['Certificate'] = Get-METCertificateFromFile -Path $CertificatePath -Password $CertificatePassword
                        }
                        catch {
                            $graphCertLoadError = $_.Exception.Message
                        }
                    }
                    else {
                        $graphParams['CertificateThumbprint'] = $CertificateThumbprint
                    }
                }
                'ManagedIdentity' {
                    $graphParams = @{ Identity = $true; NoWelcome = $true }
                }
            }

            $mgContext = Get-MgContext -ErrorAction SilentlyContinue

            # Deliberately outside the try/catch below: a tenant mismatch must hard-stop, not
            # get silently downgraded to the same Write-Warning-and-continue path used for an
            # ordinary connection failure - that path exists so Graph's optional/degrading
            # design doesn't abort the whole session, but a wrong-tenant reuse is a correctness
            # bug, not an availability one, and should never be swallowed into a warning.
            # Checked whenever $requestedOrg is known (ServicePrincipal, or Interactive with
            # -DelegatedOrganization) rather than only for ServicePrincipal - a stale Graph
            # session left over from a botched Disconnect-METSession is just as much a
            # cross-customer leak risk in the Interactive+DelegatedOrganization/MSSP case.
            # Get-MgContext always returns a GUID (even when the caller passed a domain name),
            # so $requestedOrg is resolved to a GUID via Resolve-METTenantGuid before comparing
            # - a raw string compare against a domain name would mismatch on every call.
            if ($mgContext -and $requestedOrg) {
                $expectedTenantGuid = Resolve-METTenantGuid -TenantId $requestedOrg
                if ($expectedTenantGuid -and $mgContext.TenantId -ne $expectedTenantGuid) {
                    throw "Microsoft Graph is already connected to tenant '$($mgContext.TenantId)', not the requested tenant '$requestedOrg' ($expectedTenantGuid). Run Disconnect-METSession first, then reconnect."
                }
            }

            if ($graphCertLoadError) {
                Write-Warning "Failed to connect to Microsoft Graph: $graphCertLoadError Group-membership expansion will fall back to Exchange Online cmdlets (reduced accuracy for Microsoft 365 Group references)."
            }
            else {
                try {
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
                        $servicesConnected.Add('Graph')
                    }
                    else {
                        $servicesConnected.Add('Graph')
                        Write-Verbose "Microsoft Graph already connected as $($mgContext.Account)."
                    }
                }
                catch {
                    Write-Warning "Failed to connect to Microsoft Graph: $($_.Exception.Message) Group-membership expansion will fall back to Exchange Online cmdlets (reduced accuracy for Microsoft 365 Group references). Retry with: Connect-METSession -CertificatePath <path> -CertificatePassword <securestring> for unattended use, or -DisableWAM for interactive use."
                }
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
            $teamsImportFailed = $false
            try {
                # Inside its own try so an import failure (e.g. an MSAL assembly-load
                # conflict) degrades to a warning like every other Teams failure,
                # rather than aborting a session where EXO and Graph already connected.
                Import-Module MicrosoftTeams -ErrorAction Stop
            }
            catch {
                $teamsImportFailed = $true
                Write-Warning "Failed to connect to Microsoft Teams: $($_.Exception.Message) Teams checks will be skipped."
            }

            if (-not $teamsImportFailed) {
                # Get-CsTenant throws (not returns $null) when not connected, so probe inside try/catch.
                $teamsConnection = $null
                try { $teamsConnection = Get-CsTenant -ErrorAction Stop } catch { $teamsConnection = $null }

                # Deliberately outside the try/catch below: same reasoning as the Graph leg -
                # a tenant mismatch is a correctness bug and must hard-stop, not become a warning.
                # Checked whenever $requestedOrg is known (not just ServicePrincipal) and resolved
                # to a GUID via Resolve-METTenantGuid, since Get-CsTenant's TenantId is always a
                # GUID even when the caller passed a domain name - see the Graph leg above for why.
                if ($teamsConnection -and $requestedOrg) {
                    $expectedTenantGuid = Resolve-METTenantGuid -TenantId $requestedOrg
                    if ($expectedTenantGuid -and $teamsConnection.TenantId -ne $expectedTenantGuid) {
                        throw "Microsoft Teams is already connected to tenant '$($teamsConnection.TenantId)', not the requested tenant '$requestedOrg' ($expectedTenantGuid). Run Disconnect-METSession first, then reconnect."
                    }
                }

                try {
                if (-not $teamsConnection) {
                    Write-Verbose 'Connecting to Microsoft Teams...'
                    $teamsParams = @{}
                    switch ($PSCmdlet.ParameterSetName) {
                        'Interactive' {
                            if ($UserPrincipalName) {
                                $teamsParams['AccountId'] = $UserPrincipalName
                            }
                            if ($DelegatedOrganization) {
                                # Connect-MicrosoftTeams's UserCredential set accepts -TenantId
                                # (aliases Domain/TenantDomain) for the same CSP/GDAP scenario as
                                # Graph above - previously silently ignored here too.
                                $teamsParams['TenantId'] = $DelegatedOrganization
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
                            $teamsParams['Certificate']   = if ($CertificatePath) {
                                Get-METCertificateFromFile -Path $CertificatePath -Password $CertificatePassword
                            } else {
                                Get-METCertificateByThumbprint -Thumbprint $CertificateThumbprint
                            }
                        }
                        'ManagedIdentity' {
                            $teamsParams['Identity'] = $true
                        }
                    }
                    Connect-MicrosoftTeams @teamsParams
                    $servicesConnected.Add('Teams')
                }
                else {
                    $servicesConnected.Add('Teams')
                    Write-Verbose "Microsoft Teams already connected to tenant $($teamsConnection.TenantId)."
                }
            }
            catch {
                $guidance = if ($IsWindows) {
                    'Teams checks will be skipped. Retry with: Connect-METSession -DisableWAM -Verbose'
                } else {
                    'Teams checks will be skipped. On a headless host with no reachable browser, retry with: Connect-METSession -UseDeviceAuthentication -Verbose'
                }
                if ($_.Exception -is [System.DllNotFoundException]) {
                    $guidance = 'MicrosoftTeams 7.9.0+ defaults to WAM, which is Windows-only. ' +
                                "Retry with: Connect-METSession -DisableWAM -Verbose (already applied automatically off-Windows; if it still fails and no browser is reachable at all, use -UseDeviceAuthentication)"
                }
                Write-Warning "Failed to connect to Microsoft Teams: $($_.Exception.Message) $guidance"
                }
            }
        }
    }

    $script:METConnection = @{ Mode = $requestedMode; Org = $requestedOrg }
    $script:METSessionInfo = [PSCustomObject]@{
        AuthMode          = $requestedMode
        DeviceCodeUsed    = [bool]$UseDeviceAuthentication
        TenantIdentity    = $requestedOrg
        ServicesConnected = $servicesConnected.ToArray()
        ConnectedAtUtc    = [datetime]::UtcNow
    }

    Write-Verbose 'MET session ready.'
}
