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

        try {
            $existing = Get-ConnectionInformation -ErrorAction SilentlyContinue |
                Where-Object { $_.State -eq 'Connected' } |
                Select-Object -First 1

            if (-not $existing) {
                Write-Verbose 'Connecting to Exchange Online...'
                Connect-ExchangeOnline @exoParams
            }
            else {
                Write-Verbose "Exchange Online already connected as $($existing.UserPrincipalName)."
            }
        }
        catch {
            throw "Failed to connect to Exchange Online: $_`nTry: Connect-METSession -SkipGraph -SkipTeams -UseDeviceAuthentication -Verbose`nIf that still fails, try: Connect-METSession -SkipGraph -SkipTeams -DisableWAM -Verbose"
        }
    }

    if (-not $SkipGraph) {
        $graphModuleMissing = @(
            'Microsoft.Graph.Identity.SignIns'
            'Microsoft.Graph.Groups'
        ) | Where-Object { -not (Get-Module -ListAvailable -Name $_ | Where-Object { $_.Version -ge [version]'2.0.0' }) }

        if ($graphModuleMissing) {
            throw "Required Graph module(s) not installed: $($graphModuleMissing -join ', '). Run: Install-Module '$($graphModuleMissing[0])' -Scope CurrentUser"
        }

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
                Write-Verbose 'Connecting to Microsoft Graph...'
                Connect-MgGraph @graphParams
            }
            else {
                Write-Verbose "Microsoft Graph already connected as $($mgContext.Account)."
            }
        }
        catch {
            throw "Failed to connect to Microsoft Graph: $_"
        }
    }

    if (-not $SkipTeams) {
        $teamsModule = Get-Module -ListAvailable -Name MicrosoftTeams |
            Where-Object { $_.Version -ge [version]'6.0.0' } | Select-Object -First 1
        if (-not $teamsModule) {
            Write-Warning 'MicrosoftTeams 6.x or later is not installed. Teams checks will be skipped. Install with: Install-Module MicrosoftTeams -Scope CurrentUser'
        }
        else {
            Import-Module MicrosoftTeams -ErrorAction SilentlyContinue
            try {
                # Get-CsTenant throws (not returns $null) when not connected, so probe inside try/catch.
                $teamsConnection = $null
                try { $teamsConnection = Get-CsTenant -ErrorAction Stop } catch { $teamsConnection = $null }

                if (-not $teamsConnection) {
                    Write-Verbose 'Connecting to Microsoft Teams...'
                    $teamsParams = @{}
                    switch ($PSCmdlet.ParameterSetName) {
                        'ServicePrincipal' {
                            $teamsParams['ApplicationId']         = $AppId
                            $teamsParams['TenantId']              = $TenantId
                            $teamsParams['CertificateThumbprint'] = $CertificateThumbprint
                        }
                        'ManagedIdentity' {
                            $teamsParams['ManagedIdentity'] = $true
                        }
                    }
                    Connect-MicrosoftTeams @teamsParams
                }
                else {
                    Write-Verbose "Microsoft Teams already connected to tenant $($teamsConnection.TenantId)."
                }
            }
            catch {
                Write-Warning "Failed to connect to Microsoft Teams: $_. Teams checks will produce errors."
            }
        }
    }

    Write-Verbose 'MET session ready.'
}
