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
        $checks = Test-METPrerequisites -PassThru
        $checks | Where-Object Status -like 'Fail*'

        Captures the per-component results as objects (in addition to the printed table) so the
        failing ones can be filtered and inspected programmatically.
    #>
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter()]
        [switch] $PassThru,

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
        [PSCustomObject]@{ Name = 'Microsoft.Graph.Identity.SignIns'; Min = '2.0.0'; Optional = $true  }
        [PSCustomObject]@{ Name = 'Microsoft.Graph.Groups';           Min = '2.0.0'; Optional = $true  }
        [PSCustomObject]@{ Name = 'MicrosoftTeams';                   Min = '6.0.0'; Optional = $true  }
    )

    foreach ($m in $moduleChecks) {
        $found = Get-Module -ListAvailable -Name $m.Name |
            Sort-Object Version -Descending |
            Select-Object -First 1

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

        $checks.Add([PSCustomObject]@{
            Component = $m.Name
            Required  = "$($m.Min)+"
            Installed = if ($found) { $found.Version.ToString() } else { '-' }
            Optional  = $m.Optional
            Status    = $status
            Notes     = $notes
        })
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
        Write-Warning "$(@($anyRequiredFail).Count) required prerequisite(s) not met. See notes above for install commands."
    } else {
        Write-Host '  All required prerequisites are satisfied.' -ForegroundColor Green
        Write-Host ''
    }

    if ($Quiet) { return -not [bool]$anyRequiredFail }
    if ($PassThru) { return $checks }
}
