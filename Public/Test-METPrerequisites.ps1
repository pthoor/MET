function Test-METPrerequisites {
    [CmdletBinding()]
    param()

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
        [PSCustomObject]@{ Name = 'ExchangeOnlineManagement';         Min = '3.0.0'; Optional = $false }
        # Graph is optional: Connect-METSession treats a missing module or a
        # failed connection as non-fatal, and Expand-METGroupMembership falls
        # back to Exchange Online cmdlets.
        [PSCustomObject]@{ Name = 'Microsoft.Graph.Identity.SignIns'; Min = '2.0.0'; Optional = $true  }
        [PSCustomObject]@{ Name = 'Microsoft.Graph.Groups';           Min = '2.0.0'; Optional = $true  }
        [PSCustomObject]@{ Name = 'MicrosoftTeams';                   Min = '6.0.0'; Optional = $true  }
        [PSCustomObject]@{ Name = 'Pester';                           Min = '5.0.0'; Optional = $true  }
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

    foreach ($c in $checks) {
        $color = switch -Wildcard ($c.Status) {
            'OK'     { 'Green' }
            'Fail*'  { 'Red'   }
            default  { 'Yellow'}
        }
        $tag = if ($c.Optional) { ' [optional]' } else { '' }
        Write-Host ("  {0,-42} {1}" -f "$($c.Component)$tag", $c.Status) -ForegroundColor $color
        if ($c.Notes) {
            Write-Host ("  {0,-42} {1}" -f '', $c.Notes) -ForegroundColor DarkGray
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

    return $checks
}
