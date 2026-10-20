function Test-METPrerequisites {
    <#
    .SYNOPSIS
        Checks the local PowerShell version and required/optional modules before running MET.

    .DESCRIPTION
        Verifies the PowerShell version (7.4+) and each dependency MET needs: the required
        ExchangeOnlineManagement module at its minimum version, and the optional
        Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Groups and MicrosoftTeams modules -
        a missing or outdated optional module is reported but does not fail the check, since
        Connect-METSession already degrades gracefully when Graph or Teams are unavailable. On
        non-Windows platforms it also reports whether a DNS fallback tool (dig or nslookup) is
        available for the DMARC/SPF checks, which otherwise rely on Resolve-DnsName.

        Results are always printed to the console as a coloured table. Nothing is returned by
        default; -PassThru additionally returns the check objects, and -Quiet suppresses the
        console table and returns a single boolean instead, for use in an `if` condition or a
        CI gate that only needs a yes/no answer.

    .PARAMETER PassThru
        Also returns the underlying per-component check objects (Component, Required, Installed,
        Optional, Status, Notes) to the pipeline, in addition to the console table.

    .PARAMETER TestConnection
        Also checks the live sessions Connect-METSession opened, before an assessment is run:
        that Exchange Online is connected and the account can read policy settings, that
        Microsoft Graph is connected with every scope MET requests and can read groups and
        policies, and that Microsoft Teams is connected and can read Teams settings. Each row
        names the checks a failure affects. Only Exchange Online rows are required - Graph and
        Teams rows are optional, matching how Connect-METSession degrades without them. Run
        Connect-METSession first; this switch reads existing sessions and never signs in.

    .PARAMETER Quiet
        Suppresses the console table and returns $true or $false instead, answering whether all
        required (non-optional) prerequisites are met. Without this switch, the function's
        return value is not itself a reliable yes/no answer - a non-empty array is always truthy
        in PowerShell, so `if (Test-METPrerequisites)` would evaluate to $true even when a
        required prerequisite is failing.

    .OUTPUTS
        None by default (console output only). PSCustomObject[] with -PassThru. System.Boolean
        with -Quiet.

    .EXAMPLE
        Test-METPrerequisites

        Prints a coloured table of every required and optional dependency, with install commands
        for anything missing or below its minimum version.

    .EXAMPLE
        if (-not (Test-METPrerequisites -Quiet)) {
            throw 'MET prerequisites are not met - run Test-METPrerequisites for details.'
        }

        The CI-gate pattern: fail fast, with no console table, before attempting to connect.

    .EXAMPLE
        Connect-METSession -DelegatedOrganization customer.onmicrosoft.com
        Test-METPrerequisites -TestConnection

        Confirms, before the assessment, that the signed-in account can actually read what MET
        needs in each service - for example that a tenant which requires assignment on the
        Microsoft Graph Command Line Tools enterprise app has not left Graph unconnected, or
        that consent covers every Graph scope MET requests.

    .EXAMPLE
        $checks = Test-METPrerequisites -PassThru
        $checks | Where-Object Status -like 'Fail*'

        Captures the per-component results as objects (in addition to the printed table) so the
        failing ones can be filtered and inspected programmatically.
    #>
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter()]
        [switch] $PassThru,

        [Parameter()]
        [switch] $TestConnection,

        # A Test- verb should answer a yes/no question. Without this,
        # if (Test-METPrerequisites) is always true - a non-empty array is truthy.
        [Parameter()]
        [switch] $Quiet
    )

    $checks = [System.Collections.Generic.List[PSCustomObject]]::new()

    # ── PowerShell version ───────────────────────────────────────────────────
    $psVer  = $PSVersionTable.PSVersion
    $psPass = $psVer -ge [version]'7.4'

    $checks.Add([PSCustomObject]@{
        Component = 'PowerShell'
        Required  = '7.4+'
        Installed = $psVer.ToString()
        Optional  = $false
        Status    = if ($psPass) { 'OK' } else { 'Fail' }
        Notes     = if ($psPass) { '' } else { 'Download from https://aka.ms/powershell' }
    })

    # ── Modules ──────────────────────────────────────────────────────────────
    $moduleChecks = @(
        [PSCustomObject]@{ Name = 'ExchangeOnlineManagement';         Min = '3.7.2'; Optional = $false }
        # Graph is optional: Connect-METSession treats a missing module or a
        # failed connection as non-fatal, and Expand-METGroupMembership falls
        # back to Exchange Online cmdlets.
        [PSCustomObject]@{ Name = 'Microsoft.Graph.Authentication';   Min = '2.0.0'; Optional = $true  }
        [PSCustomObject]@{ Name = 'Microsoft.Graph.Identity.SignIns'; Min = '2.0.0'; Optional = $true  }
        [PSCustomObject]@{ Name = 'Microsoft.Graph.Groups';           Min = '2.0.0'; Optional = $true  }
        [PSCustomObject]@{ Name = 'MicrosoftTeams';                   Min = '6.0.0'; Optional = $true  }
    )

    $resolvedModules = @{}
    $installedModules = @{}
    foreach ($m in $moduleChecks) {
        $installedModule = Get-Module -ListAvailable -Name $m.Name |
            Sort-Object Version -Descending |
            Select-Object -First 1
        # A module already loaded in this session is the copy that runs, whatever else is
        # installed, so it is the one judged.
        $loadedModule = Get-Module -Name $m.Name |
            Sort-Object Version -Descending |
            Select-Object -First 1
        $found = if ($loadedModule) { $loadedModule } else { $installedModule }
        $resolvedModules[$m.Name] = $found
        $installedModules[$m.Name] = $installedModule

        $versionOk = $found -and ($found.Version -ge [version]$m.Min)

        $status = if ($versionOk) {
            'OK'
        } elseif ($m.Optional -and -not $found) {
            'Not installed (optional)'
        } elseif ($m.Optional -and $found) {
            'Upgrade needed (optional)'
        } elseif (-not $found) {
            'Fail - not installed'
        } else {
            "Fail - installed $($found.Version), need $($m.Min)+"
        }

        $notes = if (-not $versionOk -and -not $m.Optional) {
            "Install-Module '$($m.Name)' -MinimumVersion '$($m.Min)' -Scope CurrentUser"
        } elseif (-not $versionOk -and $m.Optional) {
            $reason = switch -Wildcard ($m.Name) {
                'Microsoft.Graph.*' { 'group expansion falls back to Exchange Online cmdlets without it' }
                'MicrosoftTeams'    { 'Teams checks only' }
                default             { 'optional' }
            }
            "Install-Module '$($m.Name)' -MinimumVersion '$($m.Min)' -Scope CurrentUser  ($reason)"
        } else { '' }

        if ($loadedModule -and $installedModule -and $installedModule.Version -gt $loadedModule.Version) {
            $notes = "$notes $($loadedModule.Version) is loaded in this session, so that is the version checked; restart PowerShell to use the installed $($installedModule.Version).".Trim()
        }

        $checks.Add([PSCustomObject]@{
            Component = $m.Name
            Required  = "$($m.Min)+"
            Installed = if ($found) { $found.Version.ToString() } else { '-' }
            Optional  = $m.Optional
            Status    = $status
            Notes     = $notes
        })
    }

    $addRow = {
        param($Component, $Required, $Installed, $Optional, $Status, $Notes)
        $checks.Add([PSCustomObject]@{
            Component = $Component
            Required  = $Required
            Installed = $Installed
            Optional  = $Optional
            Status    = $Status
            Notes     = $Notes
        })
    }
    # Install-Module accepts -MinimumVersion only with a single -Name, so one call per module.
    $graphUpgrade = '''Microsoft.Graph.Authentication'', ''Microsoft.Graph.Groups'', ''Microsoft.Graph.Identity.SignIns'' | ForEach-Object { Install-Module -Name $_ -MinimumVersion 2.41.0 -Scope CurrentUser }'

    # ── Graph module versions ────────────────────────────────────────────────
    # Each Graph submodule pins Microsoft.Graph.Authentication to its own exact version, and
    # Connect-MgGraph loads Authentication first - so a submodule on any other version cannot
    # load beside it.
    $graphAuth = $resolvedModules['Microsoft.Graph.Authentication']
    if ($graphAuth) {
        foreach ($name in 'Microsoft.Graph.Identity.SignIns', 'Microsoft.Graph.Groups') {
            $submodule = $resolvedModules[$name]
            $row = $checks | Where-Object { $_.Component -eq $name }
            if ($submodule -and $submodule.Version -ne $graphAuth.Version -and $row.Status -eq 'OK') {
                $installedAuth = $installedModules['Microsoft.Graph.Authentication']
                $fix = if ($installedAuth -and $installedAuth.Version -eq $submodule.Version) {
                    "Restart PowerShell so the installed Microsoft.Graph.Authentication $($installedAuth.Version) loads instead."
                }
                else {
                    "Update every Graph module MET uses to the same version: $graphUpgrade"
                }
                $row.Status = 'Version mismatch (optional)'
                $row.Notes = "$name $($submodule.Version) requires Microsoft.Graph.Authentication $($submodule.Version) exactly, but $($graphAuth.Version) is the version that loads, so $name cannot load beside it. $fix"
            }
        }
    }

    # ── MSAL compatibility ───────────────────────────────────────────────────
    # Connect-METSession connects Exchange Online first, so its MSAL build is the one every
    # later module that shares the default assembly context has to live with.
    $exoModule = $resolvedModules['ExchangeOnlineManagement']
    $msalVersionOf = {
        param($Module)
        if ($Module.ModuleBase) { Get-METModuleMsalVersion -ModuleBase $Module.ModuleBase }
    }
    if ($exoModule) {
        $exoMsal = & $msalVersionOf $exoModule
        $notDetermined = 'Could not read the MSAL (Microsoft.Identity.Client) build each module bundles, so whether they can load together was not checked.'

        if ($exoMsal) {
            $sessionConflict = Test-METAssemblyLoadConflict -AssemblyName 'Microsoft.Identity.Client' -RequiredVersion $exoMsal
            if ($sessionConflict) {
                & $addRow 'MSAL loaded in this session' "MSAL $exoMsal or newer" 'Older build loaded' $false 'Fail - restart PowerShell' `
                    "$sessionConflict Exchange Online cannot connect in this session."
            }
            else {
                & $addRow 'MSAL loaded in this session' "MSAL $exoMsal or newer" 'No conflicting build loaded' $false 'OK' ''
            }
        }

        if ($graphAuth) {
            if ($graphAuth.Version -ge [version]'2.41.0') {
                & $addRow 'Graph and Exchange Online (MSAL)' 'Compatible MSAL builds' "Graph $($graphAuth.Version) loads its own MSAL" $true 'OK' ''
            }
            else {
                $graphMsal = & $msalVersionOf $graphAuth
                if (-not $exoMsal -or -not $graphMsal) {
                    & $addRow 'Graph and Exchange Online (MSAL)' 'Compatible MSAL builds' '-' $true 'Not determined (optional)' $notDetermined
                }
                elseif ($graphMsal -eq $exoMsal) {
                    & $addRow 'Graph and Exchange Online (MSAL)' 'Compatible MSAL builds' "Graph MSAL $graphMsal / Exchange Online MSAL $exoMsal" $true 'OK' ''
                }
                else {
                    & $addRow 'Graph and Exchange Online (MSAL)' 'Compatible MSAL builds' "Graph MSAL $graphMsal / Exchange Online MSAL $exoMsal" $true 'Incompatible (optional)' `
                        "Microsoft.Graph.Authentication $($graphAuth.Version) bundles MSAL $graphMsal and ExchangeOnlineManagement $($exoModule.Version) bundles $exoMsal. Graph before 2.41.0 shares one MSAL with Exchange Online and needs its own build exactly, so it will fail to connect: group expansion falls back to Exchange Online cmdlets and MET-Teams014 reports NotApplicable. Graph 2.41.0 and later load their own copy: $graphUpgrade"
                }
            }
        }

        $teamsModule = $resolvedModules['MicrosoftTeams']
        if ($teamsModule) {
            $teamsMsal = & $msalVersionOf $teamsModule
            if (-not $exoMsal -or -not $teamsMsal) {
                & $addRow 'Teams and Exchange Online (MSAL)' 'Compatible MSAL builds' '-' $true 'Not determined (optional)' $notDetermined
            }
            elseif ($teamsMsal -le $exoMsal) {
                & $addRow 'Teams and Exchange Online (MSAL)' 'Compatible MSAL builds' "Teams MSAL $teamsMsal / Exchange Online MSAL $exoMsal" $true 'OK' ''
            }
            else {
                & $addRow 'Teams and Exchange Online (MSAL)' 'Compatible MSAL builds' "Teams MSAL $teamsMsal / Exchange Online MSAL $exoMsal" $true 'Incompatible (optional)' `
                    "MicrosoftTeams $($teamsModule.Version) bundles MSAL $teamsMsal, newer than the $exoMsal that ExchangeOnlineManagement $($exoModule.Version) bundles. Connect-METSession connects Exchange Online first, and .NET cannot then load the newer MSAL Teams needs, so Teams will fail to connect and the Teams checks that use Get-Cs* cmdlets will not run. Update ExchangeOnlineManagement to a release that bundles MSAL $teamsMsal or newer: Install-Module ExchangeOnlineManagement -Scope CurrentUser"
            }
        }
    }

    # ── Platform note ────────────────────────────────────────────────────────
    if ($IsWindows -eq $false) {
        $digCommand = Get-Command dig -CommandType Application -ErrorAction SilentlyContinue
        $nslookupCommand = Get-Command nslookup -CommandType Application -ErrorAction SilentlyContinue

        $checks.Add([PSCustomObject]@{
            Component = 'Platform (DNS)'
            Required  = 'dig, nslookup, or DNS-over-HTTPS fallback'
            Installed = if ($digCommand) { 'dig found' }
                        elseif ($nslookupCommand) { 'nslookup found' }
                        else { 'DNS-over-HTTPS fallback' }
            Optional  = $false
            Status    = 'OK'
            Notes     = 'DMARC (EXO001) and SPF (EXO003) use dig or nslookup when available, and otherwise fall back to DNS-over-HTTPS on non-Windows.'
        })
    }

    # ── Connection (opt-in) ──────────────────────────────────────────────────
    if ($TestConnection) {
        $getErrorText = {
            param($ErrorRecord)
            (($ErrorRecord.Exception.Message -split "`r?`n") | ForEach-Object { $_.Trim() } | Where-Object { $_ }) -join ' '
        }
        $deniedPattern = 'Access Denied|403|Forbidden|Authorization_RequestDenied|Insufficient privileges'
        $graphCliApp = "the 'Microsoft Graph Command Line Tools' enterprise app (appId 14d82eec-204b-4c2f-b7e8-296a70dab67e)"

        # Exchange Online
        $exoSessions = if (Get-Command -Name Get-ConnectionInformation -ErrorAction SilentlyContinue) {
            @(Get-ConnectionInformation -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Connected' })
        }
        $exoOrgOf = { param($Session) if ($Session.DelegatedOrganization) { $Session.DelegatedOrganization } else { $Session.Organization } }
        # Same rule as Connect-METSession: sessions for more than one organization make cmdlet
        # routing ambiguous, so the assessment could read either customer's configuration.
        $exoOrgs = @($exoSessions | ForEach-Object { & $exoOrgOf $_ } | Where-Object { $_ } | Sort-Object -Unique)
        $exoConnection = $exoSessions | Select-Object -First 1
        if ($exoOrgs.Count -gt 1) {
            & $addRow 'Exchange Online session' 'Connected to one organization' ($exoOrgs -join ', ') $false 'Fail - multiple organizations' `
                "Exchange Online has live connections for $($exoOrgs -join ', '), so cmdlet routing between them is ambiguous and the assessment could read the wrong organization. Run Disconnect-METSession, then Connect-METSession to the one organization being assessed."
            & $addRow 'Exchange Online read access' 'Read policy settings' '-' $false 'Skipped - multiple organizations' ''
        }
        elseif ($exoConnection) {
            & $addRow 'Exchange Online session' 'Connected' "$(& $exoOrgOf $exoConnection) ($($exoConnection.UserPrincipalName))" $false 'OK' ''
            try {
                Get-HostedContentFilterPolicy -ErrorAction Stop | Select-Object -First 1 | Out-Null
                & $addRow 'Exchange Online read access' 'Read policy settings' 'Get-HostedContentFilterPolicy succeeded' $false 'OK' ''
            }
            catch {
                # Exchange Online RBAC only exposes the cmdlets the account holds a role for, so a
                # "not recognized" error here is a missing role, not a missing module.
                & $addRow 'Exchange Online read access' 'Read policy settings' 'Get-HostedContentFilterPolicy failed' $false 'Fail - access denied' `
                    "$(& $getErrorText $_) Assign the account Global Reader or Security Reader, then reconnect - an existing session does not pick up a new role."
            }
        }
        else {
            & $addRow 'Exchange Online session' 'Connected' 'Not connected' $false 'Fail - not connected' `
                'Run Connect-METSession first. Every MDO and EXO check, and MET-Teams001/002/004, need Exchange Online.'
            & $addRow 'Exchange Online read access' 'Read policy settings' '-' $false 'Skipped - not connected' ''
        }

        # Microsoft Graph
        $graphImpact = 'Without it, group expansion (MET-MDO014 and the effective-coverage checks) falls back to Exchange Online cmdlets and MET-Teams014 reports NotApplicable.'
        $mgContext = if (Get-Command -Name Get-MgContext -ErrorAction SilentlyContinue) {
            Get-MgContext -ErrorAction SilentlyContinue
        }
        if ($mgContext) {
            $graphIdentity = if ($mgContext.Account) { $mgContext.Account } else { $mgContext.ClientId }
            & $addRow 'Microsoft Graph session' 'Connected' "$graphIdentity ($($mgContext.AuthType))" $true 'OK' ''

            $coveringScopes = @{
                'Group.Read.All'        = @('Group.Read.All', 'Group.ReadWrite.All', 'Directory.Read.All', 'Directory.ReadWrite.All')
            }
            $grantedScopes = @($mgContext.Scopes)
            $missingScopes = foreach ($scope in Get-METGraphScope) {
                $accepted = if ($coveringScopes.ContainsKey($scope)) { $coveringScopes[$scope] } else { @($scope) }
                if (-not ($accepted | Where-Object { $grantedScopes -contains $_ })) { $scope }
            }
            if ($missingScopes) {
                & $addRow 'Microsoft Graph scopes' ((Get-METGraphScope) -join ', ') "Missing: $($missingScopes -join ', ')" $true 'Missing scopes (optional)' `
                    "The session's token does not carry $($missingScopes -join ', '). A tenant administrator must grant consent for them on the app the session signed in through - for interactive sign-in that is $graphCliApp - then reconnect. The read rows below show which Graph data is still reachable."
            }
            else {
                & $addRow 'Microsoft Graph scopes' ((Get-METGraphScope) -join ', ') 'All granted' $true 'OK' ''
            }

            $graphProbes = @(
                @{ Component = 'Microsoft Graph read (groups)';   Required = 'Read groups';   Impact = 'Group expansion (MET-MDO014 and the effective-coverage checks) falls back to Exchange Online cmdlets.'; Probe = { Get-MgGroup -Top 1 -ErrorAction Stop | Out-Null } }
                @{ Component = 'Microsoft Graph read (policies)'; Required = 'Read policies'; Impact = 'MET-Teams014 reports NotApplicable.'; Probe = {
                        Get-MgPolicyAuthorizationPolicy -ErrorAction Stop | Out-Null
                        Get-MgPolicyCrossTenantAccessPolicyDefault -ErrorAction Stop | Out-Null
                    } }
            )
            foreach ($probe in $graphProbes) {
                try {
                    & $probe.Probe
                    & $addRow $probe.Component $probe.Required 'Succeeded' $true 'OK' ''
                }
                catch {
                    $errorText = & $getErrorText $_
                    $status = if ($_.Exception -is [System.Management.Automation.CommandNotFoundException]) { 'Module not loaded (optional)' }
                              elseif ($errorText -match $deniedPattern) { 'Access denied (optional)' }
                              else { 'Failed (optional)' }
                    & $addRow $probe.Component $probe.Required 'Failed' $true $status "$errorText $($probe.Impact)"
                }
            }
        }
        else {
            & $addRow 'Microsoft Graph session' 'Connected' 'Not connected' $true 'Not connected (optional)' `
                "$graphImpact If Connect-METSession warned AADSTS50105 or AADSTS65001, the account is not assigned to, or lacks consent on, $graphCliApp - a tenant administrator must fix that, or connect with a service principal instead."
            & $addRow 'Microsoft Graph scopes' ((Get-METGraphScope) -join ', ') '-' $true 'Skipped - not connected' ''
            & $addRow 'Microsoft Graph read (groups)' 'Read groups' '-' $true 'Skipped - not connected' ''
            & $addRow 'Microsoft Graph read (policies)' 'Read policies' '-' $true 'Skipped - not connected' ''
        }

        # Microsoft Teams
        $teamsImpact = 'MET-Teams003, MET-Teams005 to MET-Teams012, MET-Teams015 and MET-Teams016 need it.'
        $teamsRoleFix = 'Assign the account Global Reader (the least-privileged role that can read Teams settings), then reconnect - an existing session does not pick up a new role.'
        $teamsTenant = $null
        $teamsDenied = $false
        if (Get-Command -Name Get-CsTenant -ErrorAction SilentlyContinue) {
            try { $teamsTenant = Get-CsTenant -ErrorAction Stop }
            catch { $teamsDenied = $_.Exception.Message -match 'Access Denied' }
        }
        if ($teamsTenant) {
            & $addRow 'Microsoft Teams session' 'Connected' "$($teamsTenant.DisplayName) ($($teamsTenant.TenantId))" $true 'OK' ''
            try {
                Get-CsTenantFederationConfiguration -ErrorAction Stop | Out-Null
                & $addRow 'Microsoft Teams read access' 'Read Teams settings' 'Get-CsTenantFederationConfiguration succeeded' $true 'OK' ''
            }
            catch {
                $errorText = & $getErrorText $_
                $status = if ($errorText -match $deniedPattern) { 'Access denied (optional)' } else { 'Failed (optional)' }
                & $addRow 'Microsoft Teams read access' 'Read Teams settings' 'Get-CsTenantFederationConfiguration failed' $true $status "$errorText $teamsRoleFix $teamsImpact"
            }
        }
        elseif ($teamsDenied) {
            & $addRow 'Microsoft Teams session' 'Connected' 'Connected (tenant not readable)' $true 'OK' ''
            & $addRow 'Microsoft Teams read access' 'Read Teams settings' 'Get-CsTenant: Access Denied' $true 'Access denied (optional)' "$teamsRoleFix $teamsImpact"
        }
        else {
            & $addRow 'Microsoft Teams session' 'Connected' 'Not connected' $true 'Not connected (optional)' `
                "Connect with Connect-METSession (without -SkipTeams). $teamsImpact"
            & $addRow 'Microsoft Teams read access' 'Read Teams settings' '-' $true 'Skipped - not connected' ''
        }
    }

    # ── Display ──────────────────────────────────────────────────────────────
    Write-Host ''
    Write-Host '  MET Prerequisite Check' -ForegroundColor Cyan
    Write-Host '  ─────────────────────────────────────────────────────' -ForegroundColor Cyan

    $labelWidth = (@($checks | ForEach-Object {
        "$($_.Component)$(if ($_.Optional) { ' [optional]' })".Length
    }) | Measure-Object -Maximum).Maximum + 2

    foreach ($c in $checks) {
        $color = switch -Wildcard ($c.Status) {
            'OK'     { 'Green' }
            'Fail*'  { 'Red'   }
            default  { 'Yellow'}
        }
        $tag = if ($c.Optional) { ' [optional]' } else { '' }
        Write-Host ("  {0,-$labelWidth} {1}" -f "$($c.Component)$tag", $c.Status) -ForegroundColor $color
        if ($c.Notes) {
            Write-Host ("  {0,-$labelWidth} {1}" -f '', $c.Notes) -ForegroundColor DarkGray
        }
    }

    Write-Host ''

    $required      = $checks | Where-Object { -not $_.Optional }
    $anyRequiredFail = $required | Where-Object { $_.Status -like 'Fail*' }

    if ($anyRequiredFail) {
        Write-Warning "$(@($anyRequiredFail).Count) required prerequisite(s) not met. See the notes above for how to fix each one."
    } else {
        Write-Host '  All required prerequisites are satisfied.' -ForegroundColor Green
        Write-Host ''
    }

    if ($Quiet) { return -not [bool]$anyRequiredFail }
    if ($PassThru) { return $checks }
}
