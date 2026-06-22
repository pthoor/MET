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
        [PSCustomObject]@{ Name = 'Microsoft.Graph.Identity.SignIns'; Min = '2.0.0'; Optional = $false }
        [PSCustomObject]@{ Name = 'Microsoft.Graph.Groups';           Min = '2.0.0'; Optional = $false }
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
            'Fail — not installed'
        } else {
            "Fail — installed $($found.Version), need $($m.Min)+"
        }

        $notes = if (-not $versionOk -and -not $m.Optional) {
            "Install-Module '$($m.Name)' -MinimumVersion '$($m.Min)' -Scope CurrentUser"
        } elseif (-not $versionOk -and $m.Optional) {
            "Install-Module '$($m.Name)' -MinimumVersion '$($m.Min)' -Scope CurrentUser  (Teams checks only)"
        } else { '' }

        $checks.Add([PSCustomObject]@{
            Component = $m.Name
            Required  = "$($m.Min)+"
            Installed = if ($found) { $found.Version.ToString() } else { '—' }
            Optional  = $m.Optional
            Status    = $status
            Notes     = $notes
        })
    }

    # ── Platform note ────────────────────────────────────────────────────────
    if ($IsWindows -eq $false) {
        $checks.Add([PSCustomObject]@{
            Component = 'Platform (DNS)'
            Required  = 'dig or nslookup'
            Installed = if (Get-Command dig -CommandType Application -ErrorAction SilentlyContinue) { 'dig found' }
                        elseif (Get-Command nslookup -CommandType Application -ErrorAction SilentlyContinue) { 'nslookup found' }
                        else { '—' }
            Optional  = $false
            Status    = if (Get-Command dig -CommandType Application -ErrorAction SilentlyContinue) { 'OK' }
                        elseif (Get-Command nslookup -CommandType Application -ErrorAction SilentlyContinue) { 'OK' }
                        else { 'Fail — install dig or nslookup for DMARC/SPF checks' }
            Notes     = 'DMARC (EXO001) and SPF (EXO003) require dig or nslookup on non-Windows'
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
