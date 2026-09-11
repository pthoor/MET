function Connect-METSession {
    <#
    .SYNOPSIS
        Connects the Exchange Online, Microsoft Teams and Microsoft Graph sessions MET's checks run against.

    .DESCRIPTION
        Wraps Connect-ExchangeOnline, Connect-MicrosoftTeams and Connect-MgGraph in one call and
        tracks which tenant each leg authenticated to.

        Exchange Online is a hard requirement - every MDO and EXO check needs it, and so do
        MET-Teams001, MET-Teams002 and MET-Teams004, which call Exchange-hosted cmdlets. If that
        leg fails, Connect-METSession throws. The Teams and Graph legs are optional: a failure on
        either is a warning, and the checks that need them report NotApplicable rather than
        aborting the run.

        An existing session is reused only after its tenant, organization and auth mode are
        verified to match what was requested. A mismatch throws and names the organization that
        is actually connected, rather than silently assessing the wrong customer.

    .PARAMETER UserPrincipalName
        Pre-selects the account to use for interactive sign-in, so the browser prompt does not
        ask which account to use. Interactive parameter set only.

    .PARAMETER DisableWAM
        Bypasses the Web Account Manager broker. Valid in every parameter set, not just
        Interactive - WAM affects Managed Identity and app-only flows on Windows too.
        Connect-METSession passes this automatically on Linux and macOS, where WAM does not
        apply. On Windows it is the first remedy to try for a WAM broker error such as
        'A specified logon session does not exist' (0x80070520), which usually means the
        console has no interactive desktop logon session - an elevated prompt, or a
        remote/service/scheduled-task session.

    .PARAMETER UseDeviceAuthentication
        Authenticates by device code. Device-code flow is an actively abused phishing vector
        (Storm-2372 and follow-on campaigns) - Microsoft's own current guidance is "block
        wherever possible, allow only where necessary." This is scoped to genuinely headless
        hosts where no browser can be reached at all; using it emits a warning and should be
        the last option tried, not the default retry. Interactive parameter set only.

    .PARAMETER AppId
        Application (client) ID of the service principal to authenticate as. Required with
        -CertificateThumbprint or -CertificatePath in the ServicePrincipal parameter set.

    .PARAMETER TenantId
        The tenant to authenticate against. Required for service-principal and managed-identity
        authentication. When Exchange Online is being connected (i.e. -SkipExchangeOnline is not
        used), this must be the tenant's primary .onmicrosoft.com domain name, not the tenant
        GUID - Connect-ExchangeOnline's -Organization parameter for app-only authentication
        rejects GUIDs outright, and Connect-METSession fails fast with this same guidance if it
        detects one. Graph and Teams accept either form. A GUID is only accepted alongside
        -SkipExchangeOnline.

    .PARAMETER CertificateThumbprint
        Thumbprint of a certificate in the Windows certificate store, used for service-principal
        authentication. Windows only, per Microsoft's own documentation - on Linux, macOS or a
        Codespace, use -CertificatePath and -CertificatePassword instead. Mutually exclusive with
        -CertificatePath.

    .PARAMETER CertificatePath
        Path to a PFX certificate file used for service-principal authentication. Works on any
        platform, including Linux, macOS and Codespaces, unlike -CertificateThumbprint. Requires
        -CertificatePassword. A path such as '~/cert.pfx' is resolved to an absolute path before
        use, since the underlying certificate-loading APIs do not expand '~' themselves.

    .PARAMETER CertificatePassword
        The PFX file's password, as a SecureString. Required together with -CertificatePath.

    .PARAMETER ManagedIdentity
        Authenticates using the host's managed identity (system-assigned by default, or the
        identity named by -ManagedIdentityAccountId), for MET running inside Azure Automation,
        an Azure VM, or another host with managed identity support. Mandatory in the
        ManagedIdentity parameter set.

    .PARAMETER ManagedIdentityAccountId
        Client ID of a user-assigned managed identity to use instead of the host's
        system-assigned identity. Honoured by the Exchange Online and Graph legs. Connect-MicrosoftTeams
        accepts only -Identity for managed-identity sign-in, so this is not honoured for the
        Teams leg - Teams authenticates with the host's default managed identity instead, which
        may differ from the one named here or may fail outright; pass -SkipTeams if only the
        user-assigned identity carries Teams permissions.

    .PARAMETER DelegatedOrganization
        The customer tenant to connect to under a CSP/GDAP delegated-admin relationship, as a
        domain name (e.g. 'customer.onmicrosoft.com'). Threaded through to all three legs -
        Exchange Online natively, and Graph and Teams via their own -TenantId parameter, which
        both accept a domain string for exactly this scenario. Valid in every parameter set.
        Run Disconnect-METSession before switching to a different -DelegatedOrganization in the
        same PowerShell session.

    .PARAMETER SkipExchangeOnline
        Skips the Exchange Online leg entirely. Every MDO and EXO check, and MET-Teams001/002/004,
        need Exchange Online, so checks in those areas will fail without it.

    .PARAMETER SkipGraph
        Skips the Microsoft Graph leg. Use this if you only need Exchange Online/Teams checks, or
        if Graph is unavailable - the module already treats a failed Graph connection as
        non-fatal and continues without it.

    .PARAMETER SkipTeams
        Skips the Microsoft Teams leg, for example if the MicrosoftTeams module is not installed
        or only EXO/MDO checks are being run.

    .OUTPUTS
        None. Connection state is tracked in module scope and surfaced in Get-METReport's header.

    .EXAMPLE
        Connect-METSession

        Interactive sign-in in the default browser. The usual choice for an analyst assessing
        their own tenant.

    .EXAMPLE
        Connect-METSession -AppId $appId -TenantId $tenantId -CertificateThumbprint $thumb

        Unattended service-principal sign-in on Windows, reading the certificate from the local
        certificate store - suitable for a scheduled or CI-driven assessment run from a Windows
        agent.

    .EXAMPLE
        $certPassword = ConvertTo-SecureString $env:MET_CERT_PASSWORD -AsPlainText -Force
        Connect-METSession -AppId $appId -TenantId $tenantId -CertificatePath './met-ci.pfx' -CertificatePassword $certPassword

        The same service-principal sign-in from Linux, macOS or a Codespace, where the Windows
        certificate store does not exist. This is also the recommended alternative to device-code
        auth for unattended/CI use on any non-Windows host.

    .EXAMPLE
        Connect-METSession -DelegatedOrganization customerA.onmicrosoft.com
        Invoke-METAssessment | Get-METReport -Format All -OutputPath ./assessments/customerA-2026-09-09/
        Disconnect-METSession

        An MSSP running against a customer tenant through a GDAP relationship. Run
        Disconnect-METSession before connecting to a different customer in the same PowerShell
        session - Exchange Online, Graph and Teams share one MSAL assembly context per process,
        so tenant residue between customers is a real risk.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Interactive', PositionalBinding = $false)]
    param(
        [Parameter(ParameterSetName = 'Interactive')]
        [string] $UserPrincipalName,

        # Valid in every set: WAM affects Managed Identity and app-only flows on
        # Windows too, and the README documents it as a general remedy.
        [Parameter()]
        [switch] $DisableWAM,

        [Parameter(ParameterSetName = 'Interactive')]
        [switch] $UseDeviceAuthentication,

        [Parameter(ParameterSetName = 'ServicePrincipal', Mandatory)]
        [string] $AppId,

        # Must be the tenant's primary .onmicrosoft.com domain name, not the tenant GUID, when
        # connecting Exchange Online - Connect-ExchangeOnline's -Organization parameter for
        # app-only authentication rejects GUIDs outright. Graph and Teams accept either form.
        [Parameter(ParameterSetName = 'ManagedIdentity', Mandatory)]
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

        [Parameter(ParameterSetName = 'ManagedIdentity')]
        [string] $ManagedIdentityAccountId,

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
            $PSCmdlet.ThrowTerminatingError((New-METErrorRecord `
                -Message 'Specify either -CertificateThumbprint or -CertificatePath, not both.' `
                -ErrorId 'METCertificateAmbiguous' `
                -Category ([System.Management.Automation.ErrorCategory]::InvalidArgument)))
        }
        if ($CertificateThumbprint -and -not $IsWindows) {
            $PSCmdlet.ThrowTerminatingError((New-METErrorRecord `
                -Message "-CertificateThumbprint reads the Windows certificate store and is Windows-only, per Microsoft's own documentation. On Linux/macOS use -CertificatePath <pfx> -CertificatePassword <securestring>." `
                -ErrorId 'METCertificateThumbprintWindowsOnly' `
                -Category ([System.Management.Automation.ErrorCategory]::InvalidArgument)))
        }
        if (-not $CertificateThumbprint -and -not $CertificatePath) {
            $PSCmdlet.ThrowTerminatingError((New-METErrorRecord `
                -Message 'ServicePrincipal authentication requires either -CertificateThumbprint (Windows certificate store) or -CertificatePath (works on any platform, including Linux/macOS/Codespaces).' `
                -ErrorId 'METCertificateRequired' `
                -Category ([System.Management.Automation.ErrorCategory]::InvalidArgument)))
        }
        if ($CertificatePath -and -not $CertificatePassword) {
            $PSCmdlet.ThrowTerminatingError((New-METErrorRecord `
                -Message '-CertificatePath requires -CertificatePassword.' `
                -ErrorId 'METCertificatePasswordRequired' `
                -Category ([System.Management.Automation.ErrorCategory]::InvalidArgument)))
        }
        if ($CertificatePath) {
            # Connect-ExchangeOnline's own CertificateFilePath validation calls the raw .NET
            # File.Exists() on this string, which - unlike PowerShell's own path cmdlets - never
            # expands '~' or resolves a relative path. Left alone, a path like '~/cert.pfx' fails
            # with the generic, misleading "Certificate is not accessible to the current user."
            # Resolving to an absolute path once here fixes it for the EXO, Graph, and Teams legs.
            $resolvedCertPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($CertificatePath)
            if (-not (Test-Path -LiteralPath $resolvedCertPath -PathType Leaf)) {
                $PSCmdlet.ThrowTerminatingError((New-METErrorRecord `
                    -Message "-CertificatePath '$CertificatePath' does not exist (resolved to '$resolvedCertPath')." `
                    -ErrorId 'METCertificateNotFound' `
                    -Category ([System.Management.Automation.ErrorCategory]::ObjectNotFound)))
            }
            $CertificatePath = $resolvedCertPath
        }
    }

    if ($PSCmdlet.ParameterSetName -in @('ServicePrincipal', 'ManagedIdentity') -and
        -not $SkipExchangeOnline -and
        $TenantId -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
        $PSCmdlet.ThrowTerminatingError((New-METErrorRecord `
            -Message "-TenantId must be the tenant's primary .onmicrosoft.com domain name (e.g. 'contoso.onmicrosoft.com'), not the tenant GUID - Connect-ExchangeOnline's -Organization parameter for app-only authentication rejects GUIDs. Find it in the Entra admin center under Overview > 'Primary domain', or pass -SkipExchangeOnline if you only need Graph/Teams." `
            -ErrorId 'METTenantIdMustBeDomain' `
            -Category ([System.Management.Automation.ErrorCategory]::InvalidArgument)))
    }

    # Storm-2372 and follow-on campaigns (Microsoft Security Blog, Feb 2025 - Apr 2026) abuse the
    # device-code flow's legitimate UX: an attacker generates a real device code and social-engineers
    # a victim into entering it, handing over a fully-authenticated session with no credential theft
    # or MFA bypass needed. Microsoft's own current guidance: "block device code flow wherever
    # possible... allow only where necessary."
    if ($UseDeviceAuthentication) {
        Write-Warning 'Device code authentication requested (-UseDeviceAuthentication). This flow is a documented phishing vector (Microsoft: "block wherever possible, allow only where necessary") - use it only when no browser is reachable at all (a true headless host). Prefer -DisableWAM on an interactive host, or -CertificatePath for unattended/CI use.'
    }

    # Loaded at most once per call and shared by the Graph and Teams legs. Loading the
    # PFX separately per leg doubled the key-material handling for no benefit.
    $sharedCertificate = $null

    $requestedMode = $PSCmdlet.ParameterSetName
    # Every tenant guard below (the EXO organization mismatch, the Graph and Teams tenant
    # checks, and the cross-call identity guard) is keyed on $requestedOrg. -TenantId is
    # mandatory in the ManagedIdentity set and is passed to Connect-ExchangeOnline
    # -Organization, so leaving ManagedIdentity to fall through to $null here left all four
    # unable to tell one customer's tenant from another's on that path - and
    # METSessionInfo.TenantIdentity null, so the report header could not name the tenant the
    # run was aimed at either.
    $requestedOrg = switch ($requestedMode) {
        'ServicePrincipal' { $TenantId }
        'ManagedIdentity'  { if ($DelegatedOrganization) { $DelegatedOrganization } else { $TenantId } }
        default            { if ($DelegatedOrganization) { $DelegatedOrganization } else { $null } }
    }

    # Cross-call guard within the same PowerShell process: if a prior Connect-METSession call in
    # this session already established a different identity, later legs below may reuse EXO/Graph/
    # Teams connections that Connect-METSession itself doesn't have independent proof are wrong-tenant
    # (this is the only reliable check available for Graph/Teams in Interactive+DelegatedOrganization
    # mode, since neither SDK's returned context exposes the domain name originally requested - only
    # a resolved tenant GUID). EXO gets a second, fully independent check below regardless.
    # An unspecified org must not be treated as "no conflict". Interactive without
    # -DelegatedOrganization leaves $requestedOrg null, and conditioning the comparison on
    # it being truthy meant a delegated connect followed by a bare Connect-METSession
    # reused all three of the previous customer's live sessions unverified - the same
    # cross-customer reuse this guard exists to prevent. An unspecified org against a
    # tracked org is a mismatch, not a match.
    $orgMismatch = if ($script:METConnection) {
        if ($requestedOrg -and $script:METConnection.Org) { $requestedOrg -ne $script:METConnection.Org }
        else { [bool]$requestedOrg -ne [bool]$script:METConnection.Org }
    } else { $false }

    if ($script:METConnection -and ($requestedMode -ne $script:METConnection.Mode -or $orgMismatch)) {
        $previousIdentity = if ($script:METConnection.Org) { $script:METConnection.Org } else { $script:METConnection.Mode }
        $newIdentity = if ($requestedOrg) { $requestedOrg } else { "$requestedMode (no organization specified)" }
        $PSCmdlet.ThrowTerminatingError((New-METErrorRecord `
            -Message "Connect-METSession already established a session in this PowerShell process for '$previousIdentity'. Requesting '$newIdentity' now would reuse that connection's Exchange Online/Graph/Teams sessions without actually switching tenant or auth mode. Run Disconnect-METSession first, then reconnect to the new organization." `
            -ErrorId 'METSessionIdentityMismatch' `
            -Category ([System.Management.Automation.ErrorCategory]::ResourceExists)))
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
        # Floor derived in docs/superpowers/notes/2026-09-10-exo-version-floor.md, not
        # guessed: the earliest version carrying every Connect-ExchangeOnline parameter
        # MET passes and every EXO-hosted cmdlet the checks call.
        $exoModule = Get-Module -ListAvailable -Name ExchangeOnlineManagement |
            Where-Object { $_.Version -ge [version]'3.7.2' } | Select-Object -First 1
        if (-not $exoModule) {
            $PSCmdlet.ThrowTerminatingError((New-METErrorRecord `
                -Message "ExchangeOnlineManagement 3.7.2 or later is not installed. Run: Install-Module ExchangeOnlineManagement -Scope CurrentUser" `
                -ErrorId 'METExchangeModuleMissing' `
                -Category ([System.Management.Automation.ErrorCategory]::NotInstalled)))
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
            if (Test-METExoSupportsDisableWam) {
                $exoParams['DisableWAM'] = $true
            }
            else {
                Write-Warning '-DisableWAM was requested but this ExchangeOnlineManagement build does not declare it. WAM became the default authentication broker in 3.7.0 and this switch was added in 3.7.2. Connecting without it; upgrade the module if the connection fails with a WAM broker error.'
            }
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
                # Microsoft documents -Organization as required for managed identity.
                # Without it the connection aborts, and an EXO failure is fatal, so the
                # entire parameter set was unusable.
                $exoParams['Organization']    = $TenantId
                if ($ManagedIdentityAccountId) {
                    $exoParams['ManagedIdentityAccountId'] = $ManagedIdentityAccountId
                }
            }
        }

        # Exchange Online supports concurrent sessions in one process. Checking only the
        # first connected session (the prior Select-Object -First 1) meant a process holding
        # two live connections for different customers passed this guard whenever the first
        # one happened to match the requested org, leaving the other customer's session live
        # and cmdlet routing between them ambiguous - the same class of cross-customer leak
        # the mismatch/app-only checks below exist to close, just missed for the concurrent
        # case. Refusal here is unconditional on more than one distinct org being connected,
        # regardless of whether either matches $requestedOrg: two customers' sessions live in
        # one process is itself the unsafe state. Sessions with no resolvable org (both
        # Organization and DelegatedOrganization empty) are excluded from the distinct-org set
        # rather than counted as a distinct value, so they can't spuriously trip this guard.
        $connectedSessions = @(Get-ConnectionInformation -ErrorAction SilentlyContinue |
            Where-Object { $_.State -eq 'Connected' })

        $distinctOrgs = @($connectedSessions | ForEach-Object {
            if ($_.DelegatedOrganization) { $_.DelegatedOrganization } else { $_.Organization }
        } | Where-Object { $_ } | Sort-Object -Unique)

        if ($distinctOrgs.Count -gt 1) {
            $PSCmdlet.ThrowTerminatingError((New-METErrorRecord `
                -Message "Exchange Online has $($connectedSessions.Count) live connections belonging to more than one organization ($($distinctOrgs -join ', ')). Cmdlet routing between them is ambiguous. Run Disconnect-METSession first, then reconnect to the correct organization." `
                -ErrorId 'METMultipleOrganizations' `
                -Category ([System.Management.Automation.ErrorCategory]::ResourceExists)))
        }

        $existing = $connectedSessions | Select-Object -First 1

        if ($existing) {
            # Reusing a live connection without checking whose tenant it belongs to is a
            # cross-customer data leak for -DelegatedOrganization/MSSP usage: run against
            # customer A, forget to disconnect, run against customer B - the report gets
            # labeled B but reads A's actual configuration. Organization/DelegatedOrganization
            # directly reflect what Connect-ExchangeOnline was told to connect to, regardless
            # of which one applies for this auth mode, so checking both covers every case.
            if ($requestedOrg -and $existing.Organization -ne $requestedOrg -and $existing.DelegatedOrganization -ne $requestedOrg) {
                $existingOrg = if ($existing.DelegatedOrganization) { $existing.DelegatedOrganization } else { $existing.Organization }
                $PSCmdlet.ThrowTerminatingError((New-METErrorRecord `
                    -Message "Exchange Online is already connected to '$existingOrg' (as $($existing.UserPrincipalName)), not the requested organization '$requestedOrg'. Run Disconnect-METSession first, then reconnect to the correct organization." `
                    -ErrorId 'METOrganizationMismatch' `
                    -Category ([System.Management.Automation.ErrorCategory]::ResourceExists)))
            }
            # CertificateAuthentication is only ever set for CBA connections (Microsoft's own
            # Get-ConnectionInformation docs: "the AppId parameter ... for CBA connections"), so it
            # can't distinguish interactive from Managed Identity - both are app-only, but only one
            # is certificate-based. UserPrincipalName is populated for every interactive sign-in and
            # never for an app-only session (CBA or Managed Identity alike), so it works for both.
            if ($PSCmdlet.ParameterSetName -in @('ServicePrincipal', 'ManagedIdentity') -and $existing.UserPrincipalName) {
                $PSCmdlet.ThrowTerminatingError((New-METErrorRecord `
                    -Message "Exchange Online is already connected interactively (as $($existing.UserPrincipalName)), not via app-only authentication. Run Disconnect-METSession first, then reconnect with -CertificateThumbprint/-CertificatePath or -ManagedIdentity." `
                    -ErrorId 'METAuthModeMismatch' `
                    -Category ([System.Management.Automation.ErrorCategory]::ResourceExists)))
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
                $onWindowsRetry = if ($PSCmdlet.ParameterSetName -ne 'Interactive') {
                    'Re-run with -Verbose for detail. For app-only authentication, check that the certificate is valid and not expired, that the app registration carries the required application permissions, and that admin consent has been granted.'
                }
                elseif ($IsWindows) {
                    if ("$_" -match '0x80070520|logon session does not exist|\bWAM\b|broker') {
                        "This is a WAM broker error (0x80070520 'A specified logon session does not exist'), which usually means the session is not an interactive desktop one - most often an elevated 'Run as administrator' prompt, or a remote/service/scheduled-task session. Retry from a normal non-elevated PowerShell window, or bypass WAM: Connect-METSession -DisableWAM -UserPrincipalName <upn> -Verbose"
                    }
                    else {
                        "Re-run with -Verbose for detail. If the error mentions a WAM broker or 0x80070520 ('A specified logon session does not exist'), run from a normal non-elevated PowerShell window or bypass WAM: Connect-METSession -DisableWAM -UserPrincipalName <upn> -Verbose"
                    }
                }
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
                            if (-not $sharedCertificate) {
                                $sharedCertificate = Get-METCertificateFromFile -Path $CertificatePath -Password $CertificatePassword
                            }
                            $graphParams['Certificate'] = $sharedCertificate
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
                    if ($ManagedIdentityAccountId) {
                        $graphParams['ClientId'] = $ManagedIdentityAccountId
                    }
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
                if (-not $expectedTenantGuid) {
                    # Fail closed: an unresolvable tenant GUID (e.g. a transient OIDC discovery
                    # outage) must not be treated as "no mismatch" - that would silently let a
                    # stale Graph session from a different customer be reused unverified, exactly
                    # the cross-customer leak this check exists to close.
                    $PSCmdlet.ThrowTerminatingError((New-METErrorRecord `
                        -Message "Microsoft Graph is already connected to tenant '$($mgContext.TenantId)', but the requested tenant '$requestedOrg' could not be resolved to a GUID to verify they match (the OIDC discovery lookup failed - see -Verbose). Run Disconnect-METSession first, then reconnect, or pass -TenantId as a GUID instead of a domain name." `
                        -ErrorId 'METGraphTenantMismatch' `
                        -Category ([System.Management.Automation.ErrorCategory]::ResourceExists)))
                }
                if ($mgContext.TenantId -ne $expectedTenantGuid) {
                    $PSCmdlet.ThrowTerminatingError((New-METErrorRecord `
                        -Message "Microsoft Graph is already connected to tenant '$($mgContext.TenantId)', not the requested tenant '$requestedOrg' ($expectedTenantGuid). Run Disconnect-METSession first, then reconnect." `
                        -ErrorId 'METGraphTenantMismatch' `
                        -Category ([System.Management.Automation.ErrorCategory]::ResourceExists)))
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
                    if (-not $expectedTenantGuid) {
                        # Fail closed - see the identical Graph-leg comment above for why an
                        # unresolvable GUID must not be treated as "no mismatch".
                        $PSCmdlet.ThrowTerminatingError((New-METErrorRecord `
                            -Message "Microsoft Teams is already connected to tenant '$($teamsConnection.TenantId)', but the requested tenant '$requestedOrg' could not be resolved to a GUID to verify they match (the OIDC discovery lookup failed - see -Verbose). Run Disconnect-METSession first, then reconnect, or pass -TenantId as a GUID instead of a domain name." `
                            -ErrorId 'METTeamsTenantMismatch' `
                            -Category ([System.Management.Automation.ErrorCategory]::ResourceExists)))
                    }
                    if ($teamsConnection.TenantId -ne $expectedTenantGuid) {
                        $PSCmdlet.ThrowTerminatingError((New-METErrorRecord `
                            -Message "Microsoft Teams is already connected to tenant '$($teamsConnection.TenantId)', not the requested tenant '$requestedOrg' ($expectedTenantGuid). Run Disconnect-METSession first, then reconnect." `
                            -ErrorId 'METTeamsTenantMismatch' `
                            -Category ([System.Management.Automation.ErrorCategory]::ResourceExists)))
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
                                if (-not $sharedCertificate) {
                                    $sharedCertificate = Get-METCertificateFromFile -Path $CertificatePath -Password $CertificatePassword
                                }
                                $sharedCertificate
                            } else {
                                Get-METCertificateByThumbprint -Thumbprint $CertificateThumbprint
                            }
                        }
                        'ManagedIdentity' {
                            $teamsParams['Identity'] = $true
                            # Connect-MicrosoftTeams's ManagedServiceLogin parameter set takes only
                            # -Identity plus -ManagedServiceHostName/Port/Secret; -AccountId belongs
                            # to UserCredential, so there is no supported way to select a
                            # user-assigned managed identity for the Teams leg. Passing -AccountId
                            # here would be a parameter-set binding failure, not a fix. Say so
                            # instead of letting Teams silently authenticate as a different
                            # identity than Exchange Online and Graph did.
                            if ($ManagedIdentityAccountId) {
                                Write-Warning 'Microsoft Teams does not support selecting a user-assigned managed identity: Connect-MicrosoftTeams accepts only -Identity for managed-identity sign-in, so -ManagedIdentityAccountId cannot be honoured for the Teams leg (Exchange Online and Graph do honour it). Teams will authenticate with the host''s default managed identity, which may be a different identity or may fail outright. Pass -SkipTeams if only the user-assigned identity carries Teams permissions.'
                            }
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

    # Never downgrade a tracked organization to $null. Overwriting it would destroy the
    # cross-call guard for the remainder of the process, so a later reconnect could reuse
    # this customer's sessions with nothing left to compare against.
    $retainedOrg = if ($requestedOrg) { $requestedOrg } elseif ($script:METConnection) { $script:METConnection.Org } else { $null }
    $script:METConnection = @{ Mode = $requestedMode; Org = $retainedOrg }
    $script:METSessionInfo = [PSCustomObject]@{
        AuthMode          = $requestedMode
        DeviceCodeUsed    = [bool]$UseDeviceAuthentication
        TenantIdentity    = $requestedOrg
        ServicesConnected = $servicesConnected.ToArray()
        ConnectedAtUtc    = [datetime]::UtcNow
    }

    Write-Verbose 'MET session ready.'
}
