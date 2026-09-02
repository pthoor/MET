function Get-METModuleVersion {
    [CmdletBinding()]
    param()

    $loaded = (Get-Module MET -ErrorAction SilentlyContinue)?.Version?.ToString()
    if (-not [string]::IsNullOrWhiteSpace($loaded)) { return $loaded }

    try {
        $manifestPath = Join-Path $PSScriptRoot '..' 'MET.psd1'
        $manifest = Import-PowerShellDataFile -Path $manifestPath -ErrorAction Stop
        if (-not [string]::IsNullOrWhiteSpace($manifest.ModuleVersion)) { return [string]$manifest.ModuleVersion }
    }
    catch {
        Write-Verbose "Could not resolve module version from the manifest: $($_.Exception.Message)"
    }

    return 'unknown'
}

function Get-METReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject[]] $InputObject,

        [Parameter()]
        [ValidateSet('Console','JSON','HTML','All')]
        [string] $Format = 'Console',

        [Parameter()]
        [string] $OutputPath,

        [Parameter()]
        [string] $TenantName = ''
    )

    begin {
        $allResults = [System.Collections.Generic.List[PSCustomObject]]::new()
    }

    process {
        foreach ($r in $InputObject) {
            $allResults.Add($r)
        }
    }

    end {
      $effectiveTenantName = $TenantName
      if ([string]::IsNullOrWhiteSpace($effectiveTenantName)) {
        try {
          $defaultAcceptedDomain = Get-AcceptedDomain -ErrorAction Stop |
            Where-Object { $_.Default -eq $true } |
            Select-Object -First 1

          if ($defaultAcceptedDomain -and $defaultAcceptedDomain.DomainName) {
            $effectiveTenantName = [string]$defaultAcceptedDomain.DomainName
          }
        }
        catch {
          Write-Verbose "Unable to discover default accepted domain: $($_.Exception.Message)"
        }
      }

      if ([string]::IsNullOrWhiteSpace($effectiveTenantName)) {
        $tenantFromResults = $allResults |
          ForEach-Object { [string]$_.AffectedObject } |
          Where-Object {
            $_ -match '(?i)^[a-z0-9.-]+\.onmicrosoft\.com$' -and
            $_ -notmatch '(?i)\.mail\.onmicrosoft\.com$'
          } |
          Select-Object -First 1

        if (-not [string]::IsNullOrWhiteSpace($tenantFromResults)) {
          $effectiveTenantName = $tenantFromResults
        }
      }

        $scorable = $allResults | Where-Object { $_.Result -in 'Pass','Fail','Warning' -and $null -ne $_.Score }

        $overallScore = if ($scorable) {
            $weightedSum = 0
            $weightTotal = 0
            foreach ($r in $scorable) {
                $w = Get-METCheckWeight -Severity (Get-METSafeSeverity -Severity $r.Severity)
                $weightedSum += $r.Score * $w
                $weightTotal += $w * 100
            }
            if ($weightTotal -gt 0) { [int][math]::Round(($weightedSum / $weightTotal) * 100) } else { 0 }
        } else { 0 }

        $band = if ($overallScore -ge 95) {
          'Excellent'
        }
        elseif ($overallScore -ge 80) {
          'Good'
        }
        elseif ($overallScore -ge 60) {
          'Fair'
        }
        elseif ($overallScore -ge 40) {
          'Poor'
        }
        else {
          'Critical'
        }

        $categoryScores = @{}
        foreach ($cat in @('MDO','EXO','Teams')) {
            $catResults = $scorable | Where-Object { $_.Category -eq $cat }
            if ($catResults) {
                $ws = 0; $wt = 0
                foreach ($r in $catResults) {
                    $w = Get-METCheckWeight -Severity (Get-METSafeSeverity -Severity $r.Severity)
                    $ws += $r.Score * $w
                    $wt += $w * 100
                }
                $categoryScores[$cat] = if ($wt -gt 0) { [int][math]::Round(($ws / $wt) * 100) } else { 0 }
            } else {
                $categoryScores[$cat] = $null
            }
        }

        $runTimestampUtc = [datetime]::UtcNow
        $safeTenantName = if ([string]::IsNullOrWhiteSpace($effectiveTenantName)) {
          'unknown-tenant'
        }
        else {
          ($effectiveTenantName -replace '[^a-zA-Z0-9._-]', '_')
        }
        $assessmentFolderName = '{0}-{1}' -f $runTimestampUtc.ToString('yyyyMMdd-HHmmss'), $safeTenantName

        $wantsJson = $Format -in 'JSON','All'
        $wantsHtml = $Format -in 'HTML','All'
        $resolvedJsonPath = $null
        $resolvedHtmlPath = $null
        $assessmentOutputFolder = $null
        $assessmentFolderAnnounced = $false

        if ($OutputPath -and ($wantsJson -or $wantsHtml)) {
          $outputIsDirectory = Test-Path $OutputPath -PathType Container
          $hasExtension = [System.IO.Path]::HasExtension($OutputPath)

          if ($outputIsDirectory -or -not $hasExtension -or $Format -eq 'All') {
            $baseFolder = $OutputPath
            if (-not (Test-Path $baseFolder)) {
              New-Item -ItemType Directory -Path $baseFolder -Force | Out-Null
            }
            $assessmentOutputFolder = Join-Path $baseFolder $assessmentFolderName
          }
          else {
            $parentFolder = Split-Path -Path $OutputPath -Parent
            if ([string]::IsNullOrWhiteSpace($parentFolder)) {
              $parentFolder = (Get-Location).Path
            }
            if (-not (Test-Path $parentFolder)) {
              New-Item -ItemType Directory -Path $parentFolder -Force | Out-Null
            }
            $assessmentOutputFolder = Join-Path $parentFolder $assessmentFolderName
          }

          New-Item -ItemType Directory -Path $assessmentOutputFolder -Force | Out-Null

          if ($wantsJson) {
            $jsonLeaf = if ($Format -eq 'JSON' -and $hasExtension -and -not $outputIsDirectory) {
              Split-Path -Path $OutputPath -Leaf
            }
            else {
              'MET-report.json'
            }
            $resolvedJsonPath = Join-Path $assessmentOutputFolder $jsonLeaf
          }

          if ($wantsHtml) {
            $htmlLeaf = if ($Format -eq 'HTML' -and $hasExtension -and -not $outputIsDirectory) {
              Split-Path -Path $OutputPath -Leaf
            }
            else {
              'MET-report.html'
            }
            $resolvedHtmlPath = Join-Path $assessmentOutputFolder $htmlLeaf
          }
        }

        if ($Format -eq 'All' -and -not $OutputPath) {
            $PSCmdlet.ThrowTerminatingError(
                [System.Management.Automation.ErrorRecord]::new(
                    [System.ArgumentException]::new("-OutputPath is required when -Format is 'All'. Provide a folder path to write both JSON and HTML reports."),
                    'MissingOutputPath',
                    [System.Management.Automation.ErrorCategory]::InvalidArgument,
                    $Format
                )
            )
        }

        # Error is reported as its own bucket, mutually exclusive with the Result-based
        # buckets below - a result can carry both a Result (e.g. NotApplicable, Fail) and
        # a populated Error field (e.g. Teams014 when Graph is unreachable), and counting
        # it under both would inflate the displayed total beyond the actual result count.
        $summary = @{
            Pass          = ($allResults | Where-Object { $_.Result -eq 'Pass' -and -not $_.Error }).Count
            Fail          = ($allResults | Where-Object { $_.Result -eq 'Fail' -and -not $_.Error }).Count
            Warning       = ($allResults | Where-Object { $_.Result -eq 'Warning' -and -not $_.Error }).Count
            NotApplicable = ($allResults | Where-Object { $_.Result -eq 'NotApplicable' -and -not $_.Error }).Count
            Info          = ($allResults | Where-Object { $_.Result -eq 'Info' -and -not $_.Error }).Count
            Error         = ($allResults | Where-Object { $_.Error }).Count
        }

        # Surfaces how this data was gathered - lets a customer's SOC reconcile a
        # deviceCodeFlow (or any) sign-in they see in their own logs with a known,
        # expected MET run instead of triaging it as a live incident. $null when
        # Get-METReport is called without ever going through Connect-METSession
        # (e.g. piping hand-built result objects, as the unit tests do).
        $authInfoLine = $null
        if ($script:METSessionInfo) {
            $info = $script:METSessionInfo
            $modeLabel = switch ($info.AuthMode) {
                'ServicePrincipal' { 'Service Principal (certificate)' }
                'ManagedIdentity'  { 'Managed Identity' }
                default            { if ($info.DeviceCodeUsed) { 'Interactive (device code)' } else { 'Interactive' } }
            }
            $authInfoLine = $modeLabel
            if ($info.TenantIdentity) { $authInfoLine += " - $($info.TenantIdentity)" }
            if ($info.ServicesConnected -and $info.ServicesConnected.Count) { $authInfoLine += " - $($info.ServicesConnected -join ', ')" }
        }

        # ── Console ──────────────────────────────────────────────────────────
        if ($Format -in 'Console','All') {
            Write-Host ''
            Write-Host '══════════════════════════════════════════════════════' -ForegroundColor Cyan
            Write-Host '  MET - Security Posture Scanner for MDO, EXO and Teams' -ForegroundColor Cyan
            if ($effectiveTenantName) { Write-Host "  Tenant: $effectiveTenantName" -ForegroundColor Gray }
            Write-Host "  Run:    $($runTimestampUtc.ToString('yyyy-MM-dd HH:mm')) UTC" -ForegroundColor Gray
            if ($authInfoLine) { Write-Host "  Auth:   $authInfoLine" -ForegroundColor Gray }
            Write-Host '══════════════════════════════════════════════════════' -ForegroundColor Cyan

            $scoreColor = switch ($band) {
                'Excellent' { 'Green' }
                'Good'      { 'Green' }
                'Fair'      { 'Yellow' }
                'Poor'      { 'DarkYellow' }
                default     { 'Red' }
            }
            Write-Host "  Posture Score: $overallScore / 100  [$band]" -ForegroundColor $scoreColor

            $catLine = ($categoryScores.GetEnumerator() |
                Where-Object { $null -ne $_.Value } |
                Sort-Object Name |
                ForEach-Object { "$($_.Key): $($_.Value)" }) -join '   '
            if ($catLine) { Write-Host "  $catLine" -ForegroundColor Gray }

            Write-Host "  Pass: $($summary.Pass)  Fail: $($summary.Fail)  Warning: $($summary.Warning)  N/A: $($summary.NotApplicable)  Info: $($summary.Info)  Error: $($summary.Error)"
            Write-Host ''

            $actionable = $allResults | Where-Object { $_.Result -in 'Fail','Warning' } | Sort-Object Severity, CheckId
            if ($actionable) {
                Write-Host '  Issues requiring attention:' -ForegroundColor Yellow
                $actionable | Format-Table -AutoSize -Property @(
                    @{l='CheckId';       e={ $_.CheckId }}
                    @{l='Severity';      e={ $_.Severity }}
                    @{l='Result';        e={ $_.Result }}
                    @{l='AffectedObject';e={ $_.AffectedObject }}
                    @{l='Finding';       e={
                        $f = $_.Finding
                        if ($f.Length -gt 80) { $f.Substring(0,77) + '...' } else { $f }
                    }}
                ) | Out-String | Write-Host
            } else {
                Write-Host '  No Fail or Warning findings.' -ForegroundColor Green
            }
        }

        # ── JSON ─────────────────────────────────────────────────────────────
        if ($Format -in 'JSON','All') {
            $METVersion = Get-METModuleVersion

            $jsonObj = [ordered]@{
                tenant         = $effectiveTenantName
                runTimestamp   = $runTimestampUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
                METVersion    = $METVersion
                authentication = if ($script:METSessionInfo) {
                    [ordered]@{
                        authMode          = $script:METSessionInfo.AuthMode
                        deviceCodeUsed    = $script:METSessionInfo.DeviceCodeUsed
                        tenantIdentity    = $script:METSessionInfo.TenantIdentity
                        servicesConnected = @($script:METSessionInfo.ServicesConnected)
                    }
                } else { $null }
                postureScore   = $overallScore
                categoryScores = $categoryScores
                summary        = $summary
                checks         = @($allResults | ForEach-Object {
                    [ordered]@{
                        checkId        = $_.CheckId
                        category       = $_.Category
                        name           = $_.Name
                        result         = $_.Result
                        severity       = $_.Severity
                        score          = $_.Score
                        affectedObject = $_.AffectedObject
                        finding        = $_.Finding
                        recommendation = $_.Recommendation
                        referenceUrl   = $_.ReferenceUrl
                        timestamp      = if ($_.Timestamp) { $_.Timestamp.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null }
                        error          = $_.Error
                        metadata       = $_.Metadata
                    }
                })
            }

            $json = $jsonObj | ConvertTo-Json -Depth 10

            if ($OutputPath) {
                $dest = $resolvedJsonPath

                $json | Set-Content -Path $dest -Encoding UTF8
                Write-Verbose "JSON report written to $dest"
                if ($assessmentOutputFolder -and -not $assessmentFolderAnnounced) {
                  Write-Verbose "Assessment output folder: $assessmentOutputFolder"
                  $assessmentFolderAnnounced = $true
                }
            } else {
                $json
            }
        }

        # ── HTML ─────────────────────────────────────────────────────────────
        if ($Format -in 'HTML','All') {
            $METVersion  = Get-METModuleVersion
            $runTimestamp = $runTimestampUtc.ToString('yyyy-MM-dd HH:mm') + ' UTC'
            $tenantId     = if ($effectiveTenantName) { $effectiveTenantName } else { 'unknown' }
            $tenantIdJson = $tenantId | ConvertTo-Json -Compress

            $checksData = @($allResults | ForEach-Object {
                [ordered]@{
                    checkId        = $_.CheckId
                    category       = $_.Category
                    name           = $_.Name
                    result         = $_.Result
                    severity       = $_.Severity
                    score          = $_.Score
                    affectedObject = $_.AffectedObject
                    finding        = $_.Finding
                    recommendation = $_.Recommendation
                    referenceUrl   = $_.ReferenceUrl
                    timestamp      = if ($_.Timestamp) { $_.Timestamp.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null }
                    error          = $_.Error
                    metadata       = $_.Metadata
                }
            })

            $checksJson = if ($checksData.Count -eq 0) {
                '[]'
            } else {
                $checksData | ConvertTo-Json -Depth 5 -Compress -AsArray
            }

            # Escape every '<' so embedded JSON cannot break out of the <script> block.
            # A blacklist for the literal '</script>' string is insufficient: HTML also
            # treats '</script >' / '</SCRIPT\t>' etc. as a closing tag, so any variant
            # with whitespace before '>' would bypass a literal-string replace.
            $tenantIdJson  = $tenantIdJson  -replace '<', '\u003C'
            $checksJson    = $checksJson    -replace '<', '\u003C'

            $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MET Report - $([System.Security.SecurityElement]::Escape($tenantId))</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxMDAgMTAwIj4KICA8Y2lyY2xlIGN4PSI1MCIgY3k9IjUwIiByPSI0OCIgZmlsbD0iI2YyZjFlZSI+PC9jaXJjbGU+CiAgPHBhdGggZD0iTSAyNS45NiA3NC4wNCBBIDM0IDM0IDAgMSAxIDc0LjA0IDc0LjA0IiBmaWxsPSJub25lIiBzdHJva2U9IiNkOGQ1Y2QiIHN0cm9rZS13aWR0aD0iOSIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIj48L3BhdGg+CiAgPHBhdGggZD0iTSAyNS45NiA3NC4wNCBBIDM0IDM0IDAgMSAxIDc5LjI3IDMyLjY5IiBmaWxsPSJub25lIiBzdHJva2U9Im9rbGNoKDAuNSAwLjExIDIwNSkiIHN0cm9rZS13aWR0aD0iOSIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIj48L3BhdGg+CiAgPGxpbmUgeDE9IjUwIiB5MT0iNTAiIHgyPSI3NC40IiB5Mj0iMzUuOCIgc3Ryb2tlPSIjMWMxYTE3IiBzdHJva2Utd2lkdGg9IjUiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCI+PC9saW5lPgogIDxjaXJjbGUgY3g9IjUwIiBjeT0iNTAiIHI9IjcuNSIgZmlsbD0iIzFjMWExNyI+PC9jaXJjbGU+Cjwvc3ZnPg==">
<link rel="icon" type="image/svg+xml" media="(prefers-color-scheme: dark)" href="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxMDAgMTAwIj4KICA8Y2lyY2xlIGN4PSI1MCIgY3k9IjUwIiByPSI0OCIgZmlsbD0iIzEyMTUxYSI+PC9jaXJjbGU+CiAgPHBhdGggZD0iTSAyNS45NiA3NC4wNCBBIDM0IDM0IDAgMSAxIDc0LjA0IDc0LjA0IiBmaWxsPSJub25lIiBzdHJva2U9IiMyYjMyM2MiIHN0cm9rZS13aWR0aD0iOSIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIj48L3BhdGg+CiAgPHBhdGggZD0iTSAyNS45NiA3NC4wNCBBIDM0IDM0IDAgMSAxIDc5LjI3IDMyLjY5IiBmaWxsPSJub25lIiBzdHJva2U9Im9rbGNoKDAuNjUgMC4xMyAyMDUpIiBzdHJva2Utd2lkdGg9IjkiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCI+PC9wYXRoPgogIDxsaW5lIHgxPSI1MCIgeTE9IjUwIiB4Mj0iNzQuNCIgeTI9IjM1LjgiIHN0cm9rZT0iI2YyZjFlZSIgc3Ryb2tlLXdpZHRoPSI1IiBzdHJva2UtbGluZWNhcD0icm91bmQiPjwvbGluZT4KICA8Y2lyY2xlIGN4PSI1MCIgY3k9IjUwIiByPSI3LjUiIGZpbGw9IiNmMmYxZWUiPjwvY2lyY2xlPgo8L3N2Zz4=">
<style>
:root {
  --bg: #f3f2f1;
  --surface: #ffffff;
  --surface2: #faf9f8;
  --border: #edebe9;
  --text: #201f1e;
  --text2: #605e5c;
  --text3: #a19f9d;
  --accent-mdo: #0078d4;
  --accent-exo: #008272;
  --accent-teams: #7719aa;
  --sev-critical: #d13438;
  --sev-high: #ca5010;
  --sev-medium: #986f0b;
  --sev-low: #0078d4;
  --sev-info: #8a8886;
  --result-pass: #107c10;
  --result-fail: #d13438;
  --result-warn: #ca5010;
  --result-na: #8a8886;
  --result-accepted: #0078d4;
  --shadow: 0 2px 8px rgba(0,0,0,.08);
  --radius: 4px;
  font-size: 14px;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #1b1a19;
    --surface: #252423;
    --surface2: #2d2c2b;
    --border: #3b3a39;
    --text: #f3f2f1;
    --text2: #c8c6c4;
    --text3: #8a8886;
    --shadow: 0 2px 8px rgba(0,0,0,.4);
  }
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);min-width:1024px}
a{color:var(--accent-mdo);text-decoration:none}
a:hover{text-decoration:underline}
button{font-family:inherit;cursor:pointer;border:none;background:none}

/* ── Header ──────────────────────────────────────────────────────── */
.header{background:var(--surface);border-bottom:1px solid var(--border);padding:16px 20px 16px 20px;box-shadow:var(--shadow);border-left:4px solid var(--accent-mdo);display:flex;align-items:flex-start;justify-content:space-between;gap:16px;flex-wrap:wrap}
.header-title{font-size:20px;font-weight:600;margin-bottom:3px;letter-spacing:-.01em}
.header-meta{font-size:12px;color:var(--text2)}
.header-brand{display:flex;align-items:center;gap:12px}
.header-icon{width:30px;height:30px;flex-shrink:0;color:var(--accent-mdo)}
.print-btn{font-size:12px;font-weight:600;color:var(--text2);border:1px solid var(--border);border-radius:var(--radius);padding:6px 12px;background:var(--surface2);white-space:nowrap;flex-shrink:0}
.print-btn:hover{background:var(--border);color:var(--text)}

/* ── Score banner ────────────────────────────────────────────────── */
.score-banner{background:var(--surface);border-bottom:1px solid var(--border);padding:16px 24px 16px 20px;display:flex;align-items:center;gap:32px;flex-wrap:wrap;border-left:4px solid var(--border);transition:border-left-color .3s}
.score-banner[data-band="excellent"],.score-banner[data-band="good"]{border-left-color:var(--result-pass)}
.score-banner[data-band="fair"]{border-left-color:var(--sev-medium)}
.score-banner[data-band="poor"]{border-left-color:var(--sev-high)}
.score-banner[data-band="critical"]{border-left-color:var(--result-fail)}
.score-main{display:flex;flex-direction:row;align-items:center;gap:14px}
.score-donut{flex-shrink:0}
.score-main-meta{display:flex;flex-direction:column;align-items:flex-start;gap:4px}
.score-label{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:var(--text2)}
.score-row{display:flex;align-items:baseline;gap:8px}
.score-delta{font-size:16px;font-weight:700;line-height:1}
.delta-up{color:var(--result-pass)}
.delta-down{color:var(--result-fail)}
.bar-excellent,.bar-good{background:var(--result-pass)}
.bar-fair{background:var(--sev-medium)}
.bar-poor{background:var(--sev-high)}
.bar-critical{background:var(--result-fail)}
.score-band-wrap{position:relative;display:flex;align-items:center;gap:6px;margin-top:4px}
.score-band{font-size:11px;font-weight:700;padding:3px 10px;border-radius:10px;color:#fff;letter-spacing:.06em;text-transform:uppercase}
.band-excellent,.band-good{background:var(--result-pass)}
.band-fair{background:var(--sev-medium)}
.band-poor{background:var(--sev-high)}
.band-critical{background:var(--result-fail)}
.band-info-icon{font-size:13px;color:var(--text3);cursor:default;user-select:none;line-height:1;transition:color .15s}
.score-band-wrap:hover .band-info-icon{color:var(--text2)}
.band-tooltip{position:absolute;left:0;top:calc(100% + 6px);background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);box-shadow:0 4px 16px rgba(0,0,0,.15);padding:8px 12px;min-width:190px;display:none;z-index:200;pointer-events:none}
.score-band-wrap:hover .band-tooltip,.score-band-wrap:focus-within .band-tooltip{display:block}
.btr{display:flex;align-items:center;gap:8px;padding:3px 0;color:var(--text2);font-size:12px}
.btr.cur{color:var(--text);font-weight:600}
.bdot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.brange{font-family:monospace;font-size:11px;min-width:54px;color:var(--text3)}
.btr.cur .brange{color:var(--text2)}
.cat-badge{padding:4px 12px;border-radius:10px;font-size:13px;font-weight:600;color:#fff}
.cat-mdo{background:var(--accent-mdo)}
.cat-exo{background:var(--accent-exo)}
.cat-teams{background:var(--accent-teams)}
.cat-meters{display:flex;flex-direction:column;gap:8px;min-width:220px;max-width:320px}
.cat-meter-row{display:grid;grid-template-columns:56px 1fr 28px;align-items:center;gap:8px;font-size:12px}
.cat-meter-name{font-weight:600;color:var(--text2);display:flex;align-items:center;gap:6px}
.cat-meter-dot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
.cat-meter-track{height:6px;background:var(--border);border-radius:3px;overflow:hidden}
.cat-meter-bar{height:100%;border-radius:3px;transition:width .4s ease,background .3s}
.card-cat-chip{font-size:10px;font-weight:700;padding:2px 7px;border-radius:8px;color:#fff;white-space:nowrap;flex-shrink:0;background:var(--text3)}
.cat-meter-val{text-align:right;font-weight:700;color:var(--text2)}
.score-summary{display:flex;gap:16px;flex-wrap:wrap;font-size:13px;padding-left:16px;border-left:1px solid var(--border)}
.summary-item{display:flex;flex-direction:column;align-items:center;gap:2px}
.summary-count{font-size:22px;font-weight:700}
.summary-label{font-size:11px;color:var(--text2);text-transform:uppercase;letter-spacing:.04em}
.s-pass{color:var(--result-pass)}
.s-fail{color:var(--result-fail)}
.s-warn{color:var(--result-warn)}
.s-na{color:var(--result-na)}
.s-info{color:var(--result-na)}
.s-err{color:var(--sev-critical)}

/* ── Toolbar ─────────────────────────────────────────────────────── */
.toolbar{position:sticky;top:0;z-index:30;background:var(--surface);border-bottom:1px solid var(--border);padding:0 24px;display:flex;align-items:center;gap:0;flex-wrap:wrap}
.tabs{display:flex;gap:0}
.tab{padding:12px 16px;font-size:14px;font-weight:500;color:var(--text2);border-bottom:2px solid transparent;cursor:pointer;transition:color .15s,border-color .15s;white-space:nowrap}
.tab:hover{color:var(--text)}
.tab.active{color:var(--accent-mdo);border-bottom-color:var(--accent-mdo)}
.tab .tab-count{margin-left:6px;background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:0 6px;font-size:11px;color:var(--text2)}
.filters{display:flex;align-items:center;gap:8px;margin-left:auto;padding:8px 0}
.search-box{padding:6px 10px;border:1px solid var(--border);border-radius:var(--radius);background:var(--surface2);color:var(--text);font-size:13px;width:220px}
.search-box::placeholder{color:var(--text3)}
.filter-select{padding:6px 8px;border:1px solid var(--border);border-radius:var(--radius);background:var(--surface2);color:var(--text);font-size:13px}
.result-count{font-size:12px;color:var(--text2);white-space:nowrap}

/* ── Main content ────────────────────────────────────────────────── */
.main{padding:16px 24px;display:flex;flex-direction:column;gap:16px}

/* ── Top 5 ───────────────────────────────────────────────────────── */
.top5{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow);overflow:hidden}
.top5-header{padding:12px 16px;font-weight:600;font-size:14px;display:flex;align-items:center;justify-content:space-between;cursor:pointer;user-select:none;background:var(--surface2)}
.top5-header:hover{background:var(--border)}
.top5-chevron{font-size:12px;transition:transform .2s}
.top5-chevron.open{transform:rotate(180deg)}
.top5-body{border-top:1px solid var(--border);display:none}
.top5-body.open{display:block}
.top5-row{display:grid;grid-template-columns:32px 160px 1fr auto;gap:12px;align-items:center;padding:10px 16px;border-bottom:1px solid var(--border);cursor:pointer;transition:background .1s}
.top5-row:last-child{border-bottom:none}
.top5-row:hover{background:var(--surface2)}
.top5-rank{font-size:18px;font-weight:700;color:var(--text3);text-align:center}
.top5-id{font-size:12px;font-family:monospace;color:var(--text2)}
.top5-name{font-weight:500}
.top5-finding{font-size:12px;color:var(--text2);line-height:1.5}
.finding-policy{margin-bottom:6px}.finding-policy:last-child{margin-bottom:0}
.finding-policy-name{font-weight:600;color:var(--text)}
.finding-list{margin:3px 0 0 0;padding-left:16px;list-style:disc}
.finding-list li{margin:2px 0}
.finding-list-indent{padding-left:20px}
.code-block{font-family:'Cascadia Code','Consolas',monospace;font-size:12px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:5px 10px;margin-top:6px;word-break:break-all;display:block;color:var(--text)}
.finding-code{margin-left:12px}
.inline-code{font-family:'Cascadia Code','Consolas',monospace;font-size:12px;background:var(--surface2);border:1px solid var(--border);border-radius:3px;padding:1px 5px;color:var(--text);word-break:break-word}
.coverage-wrap{margin-top:8px;overflow-x:auto}
.coverage-summary{font-size:12px;color:var(--text2);margin-bottom:8px}
.coverage-table{width:100%;border-collapse:collapse;font-size:12px}
.coverage-table th{text-align:left;padding:6px 8px;background:var(--surface2);color:var(--text2);border:1px solid var(--border);white-space:nowrap}
.coverage-table td{padding:7px 8px;border:1px solid var(--border);vertical-align:top}
.coverage-table .coverage-policy{font-weight:600;white-space:nowrap}
.coverage-table .coverage-zero{color:var(--text2)}

/* ── Cards grid ──────────────────────────────────────────────────── */
.cards{display:flex;flex-direction:column;gap:8px}
.no-results{text-align:center;padding:48px;color:var(--text2)}

/* ── Card ────────────────────────────────────────────────────────── */
.card{background:var(--surface);border:1px solid var(--border);border-left:4px solid var(--sev-info);border-radius:var(--radius);box-shadow:var(--shadow);overflow:hidden;transition:box-shadow .15s}
.card:hover{box-shadow:0 4px 16px rgba(0,0,0,.12)}
.card[data-sev="Critical"]{border-left-color:var(--sev-critical)}
.card[data-sev="High"]{border-left-color:var(--sev-high)}
.card[data-sev="Medium"]{border-left-color:var(--sev-medium)}
.card[data-sev="Low"]{border-left-color:var(--sev-low)}
.card[data-sev="Informational"]{border-left-color:var(--sev-info)}
.card[data-error="1"]{border-left-color:var(--sev-critical)}
.card-header{display:flex;align-items:center;gap:10px;padding:10px 14px;cursor:pointer;user-select:none}
.card-header:hover{background:var(--surface2)}
.card-header:focus-visible{outline:2px solid var(--accent-mdo);outline-offset:-2px}
.sev-pill{font-size:11px;font-weight:700;padding:2px 7px;border-radius:8px;color:#fff;white-space:nowrap;flex-shrink:0;background:var(--sev-info)}
.sev-critical{background:var(--sev-critical)}
.sev-high{background:var(--sev-high)}
.sev-medium{background:var(--sev-medium)}
.sev-low{background:var(--sev-low)}
.sev-informational{background:var(--sev-info)}
.card-id{font-size:12px;font-family:monospace;color:var(--text2);flex-shrink:0}
.card-name{font-weight:600;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.result-badge{font-size:12px;font-weight:700;padding:2px 8px;border-radius:8px;flex-shrink:0;color:#fff;background:var(--result-na)}
.rb-pass{background:var(--result-pass)}
.rb-fail{background:var(--result-fail)}
.rb-warning{background:var(--result-warn)}
.rb-notapplicable,.rb-info{background:var(--result-na)}
.rb-accepted{background:var(--result-accepted)}
.rb-error{background:var(--sev-critical)}
.card-chevron{font-size:11px;color:var(--text3);flex-shrink:0;transition:transform .2s}
.card-chevron.open{transform:rotate(180deg)}
.card-body{display:none;border-top:1px solid var(--border);padding:12px 14px;flex-direction:column;gap:10px}
.card-body.open{display:flex}
.card-field{display:flex;flex-direction:column;gap:2px}
.field-label{font-size:11px;font-weight:600;text-transform:uppercase;color:var(--text2);letter-spacing:.04em}
.field-value{font-size:13px;color:var(--text);white-space:pre-wrap;word-break:break-word}
.card-fix{border-top:1px solid var(--border);padding-top:10px}
.fix-toggle{display:flex;align-items:center;gap:6px;font-size:13px;font-weight:500;cursor:pointer;color:var(--accent-mdo);padding:2px 0}
.fix-toggle:hover{text-decoration:underline}
.fix-chevron{font-size:10px;transition:transform .2s}
.fix-chevron.open{transform:rotate(180deg)}
.fix-content{display:none;margin-top:8px;font-size:13px;color:var(--text);line-height:1.5}
.fix-content.open{display:block}
.fix-content ol{padding-left:18px;display:flex;flex-direction:column;gap:4px}
.card-actions{display:flex;align-items:center;gap:12px;flex-wrap:wrap;padding-top:4px}
.btn-docs{font-size:12px;color:var(--accent-mdo);padding:4px 0;display:flex;align-items:center;gap:4px}
.btn-docs:hover{text-decoration:underline}
.btn-accept{font-size:12px;color:var(--text2);border:1px solid var(--border);border-radius:var(--radius);padding:4px 10px;background:var(--surface2);transition:background .1s}
.btn-accept:hover{background:var(--border)}
.btn-undo{font-size:12px;color:var(--result-accepted);border:1px solid var(--result-accepted);border-radius:var(--radius);padding:4px 10px;background:var(--surface);transition:background .1s}
.btn-undo:hover{background:var(--surface2)}
.card-error{background:#fde7e9;border-radius:var(--radius);padding:8px 10px;font-size:12px;font-family:monospace;color:var(--sev-critical);word-break:break-word}
@media (prefers-color-scheme: dark) {
  .card-error{background:#3a1010}
}

/* ── Accept modal ────────────────────────────────────────────────── */
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:1000;align-items:center;justify-content:center}
.modal-overlay.open{display:flex}
.modal{background:var(--surface);border-radius:var(--radius);box-shadow:0 8px 32px rgba(0,0,0,.24);padding:24px;width:480px;max-width:90vw;display:flex;flex-direction:column;gap:16px}
.modal-title{font-size:16px;font-weight:600}
.modal-desc{font-size:13px;color:var(--text2)}
.modal textarea{border:1px solid var(--border);border-radius:var(--radius);padding:8px;font-family:inherit;font-size:13px;background:var(--surface2);color:var(--text);resize:vertical;min-height:80px;width:100%}
.modal textarea:focus{outline:2px solid var(--accent-mdo);border-color:transparent}
.modal-actions{display:flex;gap:8px;justify-content:flex-end}
.btn-primary{background:var(--accent-mdo);color:#fff;padding:6px 16px;border-radius:var(--radius);font-size:13px;font-weight:600;transition:opacity .1s}
.btn-primary:hover{opacity:.9}
.btn-primary:disabled{opacity:.4;cursor:not-allowed}
.btn-secondary{background:var(--surface2);color:var(--text);border:1px solid var(--border);padding:6px 16px;border-radius:var(--radius);font-size:13px}
.btn-secondary:hover{background:var(--border)}

/* ── Collapse / Expand all ───────────────────────────────────────── */
.btn-collapse{font-size:12px;color:var(--text2);border:1px solid var(--border);border-radius:var(--radius);padding:5px 10px;background:var(--surface2);transition:background .1s;white-space:nowrap}
.btn-collapse:hover{background:var(--border)}

/* ── Controls Reference ──────────────────────────────────────────── */
.ctrl-ref{display:none;flex-direction:column;gap:16px}
.ctrl-ref.visible{display:flex}
.ctrl-section{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;box-shadow:var(--shadow)}
.ctrl-section-header{padding:12px 16px;font-weight:600;display:flex;align-items:center;gap:10px;background:var(--surface2);border-bottom:1px solid var(--border);font-size:14px}
.ctrl-table{width:100%;border-collapse:collapse;font-size:13px}
.ctrl-table th{padding:8px 12px;text-align:left;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.04em;color:var(--text2);border-bottom:1px solid var(--border);background:var(--surface2)}
.ctrl-table td{padding:10px 12px;border-bottom:1px solid var(--border);vertical-align:middle}
.ctrl-table tr:last-child td{border-bottom:none}
.ctrl-row{cursor:pointer;transition:background .1s}
.ctrl-row:hover{background:var(--surface2)}
.ctrl-id{font-family:monospace;font-size:12px;white-space:nowrap;color:var(--text2)}
.ctrl-name{font-weight:500;white-space:nowrap}
.ctrl-desc{color:var(--text2)}

/* ── Print ───────────────────────────────────────────────────────── */
@media print {
  body{background:#fff}
  .toolbar,.print-btn,.modal-overlay,.band-info-icon,.card-chevron,.fix-chevron,.btn-accept,.btn-undo,.btn-collapse{display:none !important}
  .card{display:block !important;box-shadow:none;break-inside:avoid}
  .card-body{display:flex !important}
  .fix-content{display:block !important}
  #top5-section,.top5-body{display:block !important}
  #ctrl-ref,#no-results{display:none !important}
  .score-banner{break-inside:avoid}
}
</style>
</head>
<body>
<div class="header">
  <div class="header-brand">
    <svg class="header-icon" viewBox="0 0 100 100" aria-hidden="true">
      <circle cx="50" cy="50" r="48" fill="none" stroke="currentColor" stroke-width="4"></circle>
      <path d="M 25.96 74.04 A 34 34 0 1 1 74.04 74.04" fill="none" stroke="currentColor" stroke-width="9" stroke-linecap="round" opacity="0.35"></path>
      <path d="M 25.96 74.04 A 34 34 0 1 1 79.27 32.69" fill="none" stroke="currentColor" stroke-width="9" stroke-linecap="round"></path>
      <line x1="50" y1="50" x2="74.4" y2="35.8" stroke="currentColor" stroke-width="5" stroke-linecap="round"></line>
      <circle cx="50" cy="50" r="7.5" fill="currentColor"></circle>
    </svg>
    <div>
      <div class="header-title">MET - Security Posture Scanner for MDO, EXO and Teams</div>
      <div class="header-meta" id="header-meta">
        $([System.Security.SecurityElement]::Escape($(if ($effectiveTenantName) { "Tenant: $effectiveTenantName  ·  " } else { '' })))Run: $runTimestamp  ·  MET v$METVersion$([System.Security.SecurityElement]::Escape($(if ($authInfoLine) { "  ·  Auth: $authInfoLine" } else { '' })))
      </div>
    </div>
  </div>
  <button class="print-btn" type="button" id="print-btn">&#x1F5A8; Print / Export PDF</button>
</div>

<div class="score-banner" data-band="$(($band).ToLower())" id="score-banner">
  <div class="score-main">
    <svg class="score-donut" width="88" height="88" viewBox="0 0 88 88" aria-hidden="true">
      <circle cx="44" cy="44" r="36" fill="none" stroke="var(--surface2)" stroke-width="9"></circle>
      <g id="donut-segments" transform="rotate(-90 44 44)"></g>
      <text x="44" y="50" text-anchor="middle" font-size="21" font-weight="700" fill="var(--text)" id="donut-score-text">$overallScore</text>
    </svg>
    <div class="score-main-meta">
      <div class="score-label">Posture Index</div>
      <div class="score-row">
        <div class="score-delta" id="score-delta"></div>
      </div>
      <div class="score-band-wrap">
        <div class="score-band band-$(($band).ToLower())" id="score-band">$band</div>
        <div class="band-info-icon" tabindex="0" aria-label="Band scale guide">&#x24D8;</div>
        <div class="band-tooltip" id="band-tooltip" role="tooltip"></div>
      </div>
    </div>
  </div>
  <div class="cat-meters" id="cat-meters"></div>
  <div class="score-summary">
    <div class="summary-item"><span class="summary-count s-fail" id="sum-fail">$($summary.Fail)</span><span class="summary-label">Fail</span></div>
    <div class="summary-item"><span class="summary-count s-warn" id="sum-warn">$($summary.Warning)</span><span class="summary-label">Warning</span></div>
    <div class="summary-item"><span class="summary-count s-pass" id="sum-pass">$($summary.Pass)</span><span class="summary-label">Pass</span></div>
    <div class="summary-item"><span class="summary-count s-na" id="sum-na">$($summary.NotApplicable)</span><span class="summary-label">N/A</span></div>
    <div class="summary-item"><span class="summary-count s-info" id="sum-info">$($summary.Info)</span><span class="summary-label">Info</span></div>
    <div class="summary-item"><span class="summary-count s-err" id="sum-err">$($summary.Error)</span><span class="summary-label">Error</span></div>
  </div>
</div>

<div class="toolbar">
  <div class="tabs">
    <div class="tab active" data-tab="All">All <span class="tab-count" id="tc-all">0</span></div>
    <div class="tab" data-tab="Top5">Top 5 Remediation</div>
    <div class="tab" data-tab="MDO">MDO <span class="tab-count" id="tc-mdo">0</span></div>
    <div class="tab" data-tab="EXO">EXO <span class="tab-count" id="tc-exo">0</span></div>
    <div class="tab" data-tab="Teams">Teams <span class="tab-count" id="tc-teams">0</span></div>
    <div class="tab" data-tab="Accepted">Accepted <span class="tab-count" id="tc-accepted">0</span></div>
    <div class="tab" data-tab="Controls">All Controls <span class="tab-count" id="tc-controls">0</span></div>
  </div>
  <div class="filters">
    <input type="text" class="search-box" id="search" placeholder="&#x1F50D; Search...">
    <select class="filter-select" id="sev-filter">
      <option value="">All Severities</option>
      <option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Informational</option>
    </select>
    <select class="filter-select" id="result-filter">
      <option value="">All Results</option>
      <option>Fail</option><option>Warning</option><option>Pass</option><option>NotApplicable</option><option>Info</option><option>Error</option>
    </select>
    <span class="result-count" id="result-count"></span>
    <button class="btn-collapse" id="btn-collapse-all" title="Collapse or expand all visible cards">Collapse All</button>
  </div>
</div>

<div class="main">
  <div class="top5" id="top5-section">
    <div class="top5-header" id="top5-toggle">
      <span>&#x1F4CB; Top 5 Remediation Actions</span>
      <span class="top5-chevron open" id="top5-chevron">&#x25BC;</span>
    </div>
    <div class="top5-body open" id="top5-body"></div>
  </div>
  <div class="cards" id="cards-container"></div>
  <div class="no-results" id="no-results" style="display:none">No checks match the current filters.</div>
  <div class="ctrl-ref" id="ctrl-ref"></div>
</div>

<div class="modal-overlay" id="modal-overlay">
  <div class="modal">
    <div class="modal-title">Accept Risk</div>
    <div class="modal-desc" id="modal-desc">Provide a business justification for accepting this risk.</div>
    <textarea id="modal-text" placeholder="Business justification (required)..."></textarea>
    <div class="modal-actions">
      <button class="btn-secondary" id="modal-cancel">Cancel</button>
      <button class="btn-primary" id="modal-confirm" disabled>Accept Risk</button>
    </div>
  </div>
</div>

<script>
(function() {
'use strict';

const CHECKS = $checksJson;
const TENANT_ID = $tenantIdJson;
const INITIAL_SCORE = $overallScore;
const SEV_WEIGHT = {Critical:40,High:20,Medium:10,Low:5,Informational:0};
const CAT_ACCENT = {MDO:'var(--accent-mdo)',EXO:'var(--accent-exo)',Teams:'var(--accent-teams)'};

function sevOf(s){ return s || 'Informational'; }

const CONTROLS_META = {
  'MET-MDO001': 'Safe Links enabled for email and Office apps; verifies TrackClicks, EnableForInternalSenders, and real-time scanning are configured.',
  'MET-MDO002': 'Safe Attachments enabled with Block or DynamicDelivery action - flags any policy set to Allow.',
  'MET-MDO003': 'Impersonation protection, mailbox intelligence, first-contact safety tips, and action on impersonation detection.',
  'MET-MDO004': 'AuthenticationFailAction setting, DMARC honor policy, and unauthenticated sender visual indicators.',
  'MET-MDO005': 'ZAP enabled, file filter enabled, admin notifications configured, and common attachment filter active.',
  'MET-MDO006': 'SCL thresholds, bulk complaint level, high-confidence spam action, and phishing action settings.',
  'MET-MDO007': 'Auto-forward restrictions, outbound sending limits, and external forwarding rules.',
  'MET-MDO008': 'Which users and groups are covered by Standard or Strict preset policies; flags uncovered recipient gaps.',
  'MET-MDO009': 'Zero-Hour Auto Purge (ZAP) enabled for spam and phish in all active anti-spam/anti-phish policies.',
  'MET-MDO010': 'Priority account tags applied and a differentiated protection policy is active for those accounts.',
  'MET-MDO011': 'User tags are in use and alert policies referencing user tags exist.',
  'MET-MDO012': 'Safe Documents (EnableSafeDocs) enabled and AllowSafeDocsOpen disabled via AtpPolicyForO365.',
  'MET-MDO013': 'Custom anti-spam/anti-malware/Anti-Phish/Safe Links/Safe Attachments rules whose recipients are also covered by a Standard/Strict preset - flags precedence conflicts.',
  'MET-MDO014': 'Every group referenced by an enabled EOP/MDO rule\'s SentToMemberOf; reports member count and flags 0-member groups as silently inert.',
  'MET-EXO001': 'DMARC record present; policy is quarantine or reject (not none); rua reporting address configured.',
  'MET-EXO002': 'DKIM signing enabled for all accepted domains; key length is at least 2048 bits.',
  'MET-EXO003': 'SPF record present; no use of +all (pass-all); within the 10 DNS lookup limit.',
  'MET-EXO004': 'Default quarantine policies reviewed; user notification enabled; no AdminOnlyAccessPolicy on high-confidence phish quarantine.',
  'MET-EXO005': 'Stale allow entries older than 90 days; overly broad wildcard allows; ratio of allows to blocks.',
  'MET-EXO006': 'User submission mailbox configured and reporting to Microsoft enabled.',
  'MET-EXO007': 'Transport rules that bypass spam filtering (SCLJunk=-1) or disable Safe Links - informational audit.',
  'MET-EXO008': 'QuarantineRetentionPeriod is at least 30 days in all anti-spam policies (default is 15; Standard/Strict recommend 30).',
  'MET-EXO009': 'Cross-references filter policies with their assigned quarantine tag; verifies PermissionToRelease is false for Malware and High-Confidence Phish verdicts.',
  'MET-EXO010': 'RejectDirectSend on the organization config - unauthenticated senders relaying mail through the tenant\'s own domain without SMTP auth.',
  'MET-EXO011': 'Enabled inbound connectors with RequireTls off or no effective source-IP/TLS-certificate authentication binding.',
  'MET-EXO012': 'Mailbox forwarding (ForwardingSmtpAddress/ForwardingAddress/DeliverToMailboxAndForward), flagging silent forwarding with no local copy as the higher-risk pattern.',
  'MET-EXO013': 'Standing spoof-intelligence allow entries, distinguishing Internal vs. External spoof type.',
  'MET-EXO014': 'Enforceable phishing-simulation and SecOps mailbox override rules - informational listing for periodic review.',
  'MET-EXO015': 'The native Outlook "External" sender banner (Get-ExternalInOutlook) - a user-facing signal against lookalike-domain/BEC senders.',
  'MET-EXO016': 'ARC trusted sealer domains (Get-ArcConfig) - informational listing of domains trusted to vouch for authentication results.',
  'MET-EXO017': 'EndUserSpamNotificationFrequency on the tenant-wide global quarantine policy - informational cadence listing.',
  'MET-EXO018': 'Remote domain AutoForwardEnabled - whether automatic forwarding to external domains is permitted, the control plane behind inbox-rule exfiltration.',
  'MET-EXO019': 'Tenant-wide SmtpClientAuthenticationDisabled plus per-mailbox overrides - legacy SMTP AUTH is a basic-auth endpoint exempt from most conditional access.',
  'MET-EXO020': 'Connection filter IPAllowList and EnableSafeList - allow-listed sources skip spam filtering and spoof intelligence entirely.',
  'MET-EXO021': 'Organization-wide AuditDisabled - whether mailbox audit records exist to reconstruct what a compromised account accessed.',
  'MET-EXO022': 'Sharing policies exposing calendar detail or contacts to all domains or anonymously - reconnaissance surface for internal-impersonation phishing.',
  'MET-EXO023': 'UnifiedAuditLogIngestionEnabled - the tenant-wide record investigations are reconstructed from; retention is not asserted by this check.',
  'MET-Teams001': 'EnableSafeLinksForTeams enabled in Safe Links policies that cover Teams users.',
  'MET-Teams002': 'Global EnableATPForSPOTeamsODB enabled; EnableSafeAttachmentsForTeams enabled in at least one policy.',
  'MET-Teams003': 'External access settings, anonymous join policy, and lobby bypass settings reviewed for security posture.',
  'MET-Teams004': 'TeamsProtectionPolicy ZAP enabled; malware and high-confidence phish quarantine tags set to AdminOnlyAccessPolicy.',
  'MET-Teams005': 'ReportTeamsMsgEnabled in submission policy and AllowSecurityEndUserReporting in Teams messaging policy.',
  'MET-Teams006': 'Tenant federation config - open AllowAllKnownDomains federation, Teams consumer/personal-account access, and an empty BlockedDomains deny-list.',
  'MET-Teams007': 'Guest messaging/calling configuration - AllowUserChat and AllowPrivateCalling for guest accounts.',
  'MET-Teams008': 'App permission policies not restricted to an explicit AllowedAppList/BlockedAppList for global/private/store catalog apps.',
  'MET-Teams009': 'ExternalAccessWithTrialTenants on the tenant federation config - exposure to disposable trial-tenant federation.',
  'MET-Teams010': 'Per-user CsExternalAccessPolicy instances re-opening federation/public-cloud access for specific users under a restrictive tenant baseline.',
  'MET-Teams011': 'SecurityTeamAllowBlockListDelegation and currently-blocked entities - whether SecOps can block malicious domains/users mid-incident.',
  'MET-Teams012': 'ReportCall on Teams calling policies - closest native control to helpdesk-vishing attacks over a Teams call.',
  'MET-Teams014': 'Cross-tenant access and authorization policy (Microsoft Graph) - guest invitation and external collaboration settings.',
  'MET-Teams015': 'AllowEmailIntoChannel on the Teams client configuration - channel email addresses accept external mail that bypasses the mailbox delivery path.'
};

const CONTROLS_CATEGORIES = [
  { id: 'MDO',   label: 'Microsoft Defender for Office 365', cls: 'cat-mdo'   },
  { id: 'EXO',   label: 'Exchange Online / Email Authentication', cls: 'cat-exo'   },
  { id: 'Teams', label: 'Microsoft Teams Protection',         cls: 'cat-teams' }
];

// ── localStorage helpers ─────────────────────────────────────────
// Some browsers (notably Safari) throw a SecurityError accessing localStorage
// on file:// pages. Fall back to an in-memory store so the report still
// renders and works for the current session instead of crashing outright.
const memStore = {};
function lsGet(key) {
  try { return localStorage.getItem(key); } catch (e) { return Object.prototype.hasOwnProperty.call(memStore, key) ? memStore[key] : null; }
}
function lsSet(key, val) {
  try { localStorage.setItem(key, val); } catch (e) { memStore[key] = val; }
}
function lsRemove(key) {
  try { localStorage.removeItem(key); } catch (e) { delete memStore[key]; }
}
function lsKey(checkId){ return 'MET_accepted_' + TENANT_ID + '_' + checkId; }
function isAccepted(checkId){ return !!lsGet(lsKey(checkId)); }
function getJustification(checkId){ return lsGet(lsKey(checkId)); }
function setAccepted(checkId, justification){ lsSet(lsKey(checkId), justification || 'Accepted'); }
function clearAccepted(checkId){ lsRemove(lsKey(checkId)); }

// ── Score calculation ────────────────────────────────────────────
function bandOf(score) {
  return score >= 95 ? 'Excellent' : score >= 80 ? 'Good' : score >= 60 ? 'Fair' : score >= 40 ? 'Poor' : 'Critical';
}
function weightedScore(checks) {
  let wSum = 0, wTotal = 0;
  checks.forEach(function(c) {
    if (!['Pass','Fail','Warning'].includes(c.result)) return;
    if (c.score === null || c.score === undefined) return;
    if (isAccepted(c.checkId)) return;
    const w = SEV_WEIGHT[c.severity] || 0;
    wSum  += c.score * w;
    wTotal += w * 100;
  });
  return wTotal > 0 ? Math.round((wSum / wTotal) * 100) : null;
}
function recalcScore() {
  const score = weightedScore(CHECKS) ?? 0;
  const band = bandOf(score);
  document.getElementById('donut-score-text').textContent = score;
  const bandEl = document.getElementById('score-band');
  bandEl.textContent = band;
  bandEl.className = 'score-band band-' + band.toLowerCase();
  const banner = document.getElementById('score-banner');
  if (banner) banner.dataset.band = band.toLowerCase();
  renderBandTooltip(band);
  renderCatMeters();
  renderDonut();
}

const BAND_SCALE = [
  { label:'Excellent', range:'95–100', color:'var(--result-pass)' },
  { label:'Good',      range:'80–94',  color:'var(--result-pass)' },
  { label:'Fair',      range:'60–79',  color:'var(--sev-medium)'  },
  { label:'Poor',      range:'40–59',  color:'var(--sev-high)'    },
  { label:'Critical',  range:'0–39',   color:'var(--result-fail)' }
];
function renderBandTooltip(currentBand) {
  const el = document.getElementById('band-tooltip');
  if (!el) return;
  el.innerHTML = BAND_SCALE.map(function(b) {
    const isCur = b.label === currentBand;
    return '<div class="btr' + (isCur ? ' cur' : '') + '">' +
      '<span class="bdot" style="background:' + b.color + '"></span>' +
      '<span class="brange">' + b.range + '</span>' +
      '<span>' + b.label + (isCur ? ' ◄' : '') + '</span>' +
      '</div>';
  }).join('');
}

// ── Category score meters ──────────────────────────────────────────
// Bar color reports how healthy the category is (same 5 bands as the score banner);
// the dot next to the label is what says which category it is.
function renderCatMeters() {
  const el = document.getElementById('cat-meters');
  if (!el) return;
  el.innerHTML = ['MDO','EXO','Teams'].map(function(cat) {
    const score = weightedScore(CHECKS.filter(function(c) { return c.category === cat; }));
    if (score === null) return '';
    return '<div class="cat-meter-row">' +
      '<span class="cat-meter-name"><span class="cat-meter-dot" style="background:' + CAT_ACCENT[cat] + '"></span>' + cat + '</span>' +
      '<div class="cat-meter-track"><div class="cat-meter-bar bar-' + bandOf(score).toLowerCase() + '" style="width:' + score + '%"></div></div>' +
      '<span class="cat-meter-val">' + score + '</span>' +
    '</div>';
  }).join('');
}

// ── Result distribution donut ──────────────────────────────────────
function renderDonut() {
  const g = document.getElementById('donut-segments');
  if (!g) return;
  g.innerHTML = '';
  // Error is its own bucket, mutually exclusive with every Result-based bucket below - matches
  // the server-rendered initial summary (Get-METReport.ps1's $summary hashtable). A result can
  // carry both a Result and a populated Error field (e.g. Teams014 when Graph is unreachable);
  // counting it under both would double-count it across the Error badge and its Result segment.
  const fail  = CHECKS.filter(function(c) { return c.result === 'Fail' && !isAccepted(c.checkId) && !c.error; }).length;
  const warn  = CHECKS.filter(function(c) { return c.result === 'Warning' && !isAccepted(c.checkId) && !c.error; }).length;
  const pass  = CHECKS.filter(function(c) { return c.result === 'Pass' && !c.error; }).length;
  const na    = CHECKS.filter(function(c) { return c.result === 'NotApplicable' && !c.error; }).length;
  const info  = CHECKS.filter(function(c) { return c.result === 'Info' && !c.error; }).length;
  const error = CHECKS.filter(function(c) { return !!c.error; }).length;
  const total = fail + warn + pass + na + info + error;
  document.getElementById('sum-fail').textContent = fail;
  document.getElementById('sum-warn').textContent = warn;
  if (!total) return;
  const segs = [
    { v: fail,  color: 'var(--result-fail)'   },
    { v: warn,  color: 'var(--result-warn)'   },
    { v: pass,  color: 'var(--result-pass)'   },
    { v: na,    color: 'var(--result-na)'     },
    { v: info,  color: 'var(--result-na)'     },
    { v: error, color: 'var(--sev-critical)'  }
  ].filter(function(s) { return s.v > 0; });
  const r = 36, circ = 2 * Math.PI * r;
  let offset = 0;
  segs.forEach(function(s) {
    const len = (s.v / total) * circ;
    const c = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    c.setAttribute('cx', 44); c.setAttribute('cy', 44); c.setAttribute('r', r);
    c.setAttribute('fill', 'none'); c.setAttribute('stroke', s.color); c.setAttribute('stroke-width', 9);
    c.setAttribute('stroke-dasharray', len + ' ' + (circ - len));
    c.setAttribute('stroke-dashoffset', -offset);
    g.appendChild(c);
    offset += len;
  });
}

// ── Escape HTML ──────────────────────────────────────────────────
// Only null/undefined collapse to empty. A falsy-but-real value (0, false) must
// still render - a policy at Priority 0 is the highest-precedence policy, and
// blanking that cell hides exactly the row an operator is looking for.
function esc(s) {
  if (s === null || s === undefined) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
// CSS class fragments are built from check-supplied Result/Severity/Category values
// and interpolated into class="..." attributes. Lowercasing alone is not a defence -
// every character needed to break out of an attribute survives it. Reduce to the
// character set a class name can legitimately contain; anything else becomes
// 'unknown', which the stylesheet renders with a visible neutral fallback.
function slug(s) {
  const out = String(s === null || s === undefined ? '' : s).toLowerCase().replace(/[^a-z0-9-]/g, '');
  return out || 'unknown';
}
// Format finding text into a structured bullet list.
// Multi-policy findings arrive as "PolicyName: issue1; issue2\nPolicyName2: issue3".
// Single-policy findings arrive as "issue1; issue2; issue3" (no \n, no prefix).
// A " | " separator marks a technical value (DNS record, CNAME, etc.) rendered as a code block.
function splitPipe(s) {
  var idx = s.indexOf(' | ');
  return idx !== -1 ? [s.substring(0, idx).trim(), s.substring(idx + 3).trim()] : [s.trim(), null];
}
function codeBlockHtml(val) {
  return val ? '<code class="code-block finding-code">' + esc(val) + '</code>' : '';
}
// Findings are often authored as one sentence joined with '; ' (e.g. "X is
// disabled; users lose Y"), then split into separate bullets - capitalize
// each bullet so it reads as its own sentence instead of a sentence
// fragment. Leaves already-capitalized or symbol/digit-led text alone.
function capFirst(s) {
  return /^[a-z]/.test(s) ? s.charAt(0).toUpperCase() + s.slice(1) : s;
}
function fmtFinding(s) {
  if (!s) return '';
  var normalized = s.replace(/·|–|-|―/g, '-');
  var lines = normalized.split('\n').filter(function(l){ return l.trim(); });

  if (lines.length <= 1) {
    var parts = splitPipe(normalized);
    var text = parts[0], code = parts[1];
    var issues = text.split(/;\s*/).filter(function(i){ return i.trim(); });
    var issuesHtml = issues.length <= 1 ? codifyQuotes(text) :
      '<ul class="finding-list">' + issues.map(function(i){ return '<li>' + codifyQuotes(capFirst(i.trim())) + '</li>'; }).join('') + '</ul>';
    return issuesHtml + codeBlockHtml(code);
  }

  return lines.map(function(line) {
    var parts = splitPipe(line);
    var mainLine = parts[0], code = parts[1];
    var sep = mainLine.indexOf(': ');
    var policyName = sep !== -1 ? mainLine.substring(0, sep).trim() : mainLine;
    var issueStr   = sep !== -1 ? mainLine.substring(sep + 2).trim() : '';
    var issues = issueStr.split(/;\s*/).filter(function(i){ return i.trim(); });
    return '<div class="finding-policy">' +
      '<div class="finding-policy-name">&#x2022;&nbsp;' + esc(policyName) + '</div>' +
      (issues.length ? '<ul class="finding-list finding-list-indent">' +
        issues.map(function(i){ return '<li>' + codifyQuotes(capFirst(i.trim())) + '</li>'; }).join('') +
        '</ul>' : '') +
      codeBlockHtml(code) +
      '</div>';
  }).join('');
}
function fmtEffectivePolicyCoverage(check) {
  const metadata = check.metadata;
  if (!metadata || metadata.DetailType !== 'EffectivePolicyCoverage') return '';
  const policies = Array.isArray(metadata.Policies) ? metadata.Policies : [];
  const rows = policies.map(function(policy) {
    const count = Number(policy.EffectiveRecipientCount || 0);
    const priority = policy.Priority === null || policy.Priority === undefined ? 'N/A' : policy.Priority;
    const issues = Array.isArray(policy.Issues) && policy.Issues.length ? policy.Issues.join('; ') : 'None';
    const observations = Array.isArray(policy.OrderingObservations) && policy.OrderingObservations.length ? policy.OrderingObservations.join('; ') : 'None';
    return '<tr class="' + (count === 0 ? 'coverage-zero' : '') + '">' +
      '<td class="coverage-policy">' + esc(policy.PolicyName) + '</td>' +
      '<td>' + esc(policy.PolicyType) + '</td>' +
      '<td>' + esc(policy.State) + '</td>' +
      '<td>' + esc(priority) + '</td>' +
      '<td>' + esc(policy.Scope) + '</td>' +
      '<td>' + count + ' of ' + Number(metadata.TotalRecipients || 0) + '</td>' +
      '<td>' + esc(policy.ConfigurationStatus) + '</td>' +
      '<td>' + esc(policy.CurrentImpact) + '</td>' +
      '<td>' + esc(observations) + '</td>' +
      '<td>' + esc(issues) + '</td>' +
    '</tr>';
  }).join('');
  const protectionType = metadata.ProtectionType || 'Threat protection';
  const recommendations = Array.isArray(metadata.CoverageRecommendations) ? metadata.CoverageRecommendations : [];
  const recommendationHtml = recommendations.length ? '<div class="coverage-summary"><strong>Coverage recommendations:</strong><ul>' + recommendations.map(function(item) { return '<li>' + esc(item) + '</li>'; }).join('') + '</ul></div>' : '';
  return '<div class="coverage-wrap">' +
    '<div class="coverage-summary">Effective ' + esc(protectionType) + ' policy coverage: ' +
      Number(metadata.CompliantRecipients || 0) + ' of ' + Number(metadata.TotalRecipients || 0) +
      ' recipients meet the configured baseline.</div>' +
    recommendationHtml + '<table class="coverage-table"><thead><tr>' +
      '<th>Policy</th><th>Type</th><th>State</th><th>Priority</th><th>Scope</th>' +
      '<th>Effective recipients</th><th>Configuration</th><th>Current impact</th><th>Ordering observations</th><th>Issues</th>' +
    '</tr></thead><tbody>' + rows + '</tbody></table></div>';
}
// Validating the scheme is not enough: the return value is interpolated into an
// href="..." attribute, and new URL() accepts quotes and angle brackets in a path,
// so an https: URL can still break out of the attribute and inject markup. The
// validated URL must be HTML-escaped before it reaches the attribute.
function safeHref(url) {
  if (!url) return '#';
  try { const u = new URL(url); return (u.protocol === 'https:' || u.protocol === 'http:') ? esc(u.href) : '#'; }
  catch { return '#'; }
}

// ── Inline-code formatting for finding/recommendation text ────────
// 'quoted' technical values (setting names, DNS records), bare SPF
// qualifier tokens (+all, -all, ~all, ?mx, ...), bare key=value tokens
// (p=none, p=quarantine, rua=mailto:...), and the command portion of a
// "Run: <cmdlet>" instruction are all rendered as inline code.
function codifyQuotes(s) {
  const re = /'([^']+)'|(^|[\s(])([+\-~?](?:all|mx|a|ip4|ip6|include|exists|ptr|redirect)\b|[a-zA-Z][\w-]*=[^\s,;()]*[^\s,;().])/g;
  let out = '', lastIndex = 0, m;
  while ((m = re.exec(s)) !== null) {
    out += esc(s.slice(lastIndex, m.index));
    if (m[1] !== undefined) {
      out += '<code class="inline-code">' + esc(m[1]) + '</code>';
    } else {
      out += esc(m[2]) + '<code class="inline-code">' + esc(m[3]) + '</code>';
    }
    lastIndex = re.lastIndex;
  }
  out += esc(s.slice(lastIndex));
  return out;
}
function codifyRecText(s) {
  const runMatch = s.match(/^Run:\s+(.+?)(\.\s+|\.$|$)/);
  if (runMatch) {
    const cmd  = runMatch[1];
    const rest = s.slice(runMatch[0].length);
    return 'Run: <code class="inline-code">' + esc(cmd) + '</code>' + esc(runMatch[2]) + codifyQuotes(rest);
  }
  return codifyQuotes(s);
}

// ── Build recommendation as list if multi-line ───────────────────
function buildRecommendation(rec) {
  if (!rec) return '';
  const lines = rec.split(/\n/).map(function(l){ return l.trim(); }).filter(Boolean);
  if (lines.length <= 1) return '<p>' + codifyRecText(rec) + '</p>';
  return '<ol>' + lines.map(function(l){ return '<li>' + codifyRecText(l.replace(/^\d+\.\s*/, '')) + '</li>'; }).join('') + '</ol>';
}

// ── Render a single card ─────────────────────────────────────────
function createCard(check) {
  const accepted   = isAccepted(check.checkId);
  const hasError   = !!check.error;
  const isFailWarn = ['Fail','Warning'].includes(check.result);
  const showFix    = isFailWarn || hasError;
  const isPass     = check.result === 'Pass';
  // A check can carry both a Result (e.g. NotApplicable) and a populated Error field when it
  // couldn't run - the badge must say ERROR so the card is findable, even though card.dataset.result
  // (used by the result-filter dropdown and tab scoping below) stays the real Result value. hasError
  // wins over accepted: a synthetic Fail from a crashed check (see Invoke-METTriage's per-check catch)
  // can be risk-accepted like any other Fail, and an accepted check still carrying an Error is exactly
  // the "error with no findable card" bug this fix closes - just for accepted checks instead of all of them.
  const resultDisplay = hasError ? 'Error' : (accepted ? 'Accepted' : check.result);
  const rbClass    = 'rb-' + (hasError ? 'error' : (accepted ? 'accepted' : slug(check.result)));
  const startOpen  = false;

  const card = document.createElement('div');
  card.className = 'card';
  card.dataset.checkId  = check.checkId;
  card.dataset.category = check.category;
  card.dataset.result   = check.result;
  card.dataset.sev      = sevOf(check.severity);
  card.dataset.accepted = accepted ? '1' : '0';
  card.dataset.error    = hasError ? '1' : '0';
  card.dataset.search   = [check.checkId, check.name, check.affectedObject, check.finding].join(' ').toLowerCase();

  const bodyOpen = startOpen ? ' open' : '';

  let actionsHtml = '';
  if (check.referenceUrl) {
    actionsHtml += '<a class="btn-docs" href="' + safeHref(check.referenceUrl) + '" target="_blank" rel="noopener">&#x1F4D6; Microsoft Docs</a>';
  }
  if (['Fail','Warning'].includes(check.result) && !accepted) {
    actionsHtml += '<button class="btn-accept" data-checkid="' + esc(check.checkId) + '">&#x2713; Accept Risk</button>';
  }
  if (accepted) {
    const just = esc(getJustification(check.checkId));
    actionsHtml += '<span style="font-size:12px;color:var(--result-accepted)">Accepted: ' + just + '</span>';
    actionsHtml += '<button class="btn-undo" data-checkid="' + esc(check.checkId) + '">Undo acceptance</button>';
  }

  const errorHtml = check.error
    ? '<div class="card-error">Check failed: ' + esc(check.error) + '</div>'
    : '';
  const coverageHtml = fmtEffectivePolicyCoverage(check);

  const fixHtml = (check.recommendation || errorHtml) ? (
    '<div class="card-fix">' +
    '<div class="fix-toggle" tabindex="0" role="button">' +
    '<span class="fix-chevron">&#x25BA;</span> How to fix</div>' +
    '<div class="fix-content">' +
    (errorHtml || buildRecommendation(check.recommendation)) +
    '</div></div>'
  ) : '';

  card.innerHTML =
    '<div class="card-header" role="button" tabindex="0" aria-expanded="' + (startOpen ? 'true' : 'false') + '">' +
      '<span class="sev-pill sev-' + slug(sevOf(check.severity)) + '">' + esc(sevOf(check.severity).toUpperCase()) + '</span>' +
      '<span class="card-cat-chip cat-' + slug(check.category) + '">' + esc(check.category) + '</span>' +
      '<span class="card-id">' + esc(check.checkId) + '</span>' +
      '<span class="card-name">' + esc(check.name) + '</span>' +
      '<span class="result-badge ' + rbClass + '">' + esc(resultDisplay.toUpperCase()) + '</span>' +
      '<span class="card-chevron' + (startOpen ? ' open' : '') + '">&#x25BC;</span>' +
    '</div>' +
    '<div class="card-body' + bodyOpen + '">' +
      '<div class="card-field"><span class="field-label">Affected Object</span><span class="field-value">' + esc(check.affectedObject) + '</span></div>' +
      '<div class="card-field"><span class="field-label">Finding</span><span class="field-value">' + fmtFinding(check.finding) + '</span></div>' +
      (coverageHtml ? '<div class="card-field"><span class="field-label">Effective Policy Coverage</span><span class="field-value">' + coverageHtml + '</span></div>' : '') +
      fixHtml +
      '<div class="card-actions">' + actionsHtml + '</div>' +
    '</div>';

  // Toggle card body; auto-open fix section on first expand of Fail/Warning
  const cardHeader = card.querySelector('.card-header');
  cardHeader.addEventListener('click', function() {
    const body    = card.querySelector('.card-body');
    const chevron = card.querySelector('.card-chevron');
    const isOpen  = body.classList.toggle('open');
    chevron.classList.toggle('open', isOpen);
    this.setAttribute('aria-expanded', isOpen);
    if (isOpen && showFix && !card.dataset.fixOpened) {
      card.dataset.fixOpened = '1';
      const fixContent = card.querySelector('.fix-content');
      const fixChev    = card.querySelector('.fix-chevron');
      if (fixContent && !fixContent.classList.contains('open')) {
        fixContent.classList.add('open');
        if (fixChev) fixChev.classList.add('open');
      }
    }
  });
  cardHeader.addEventListener('keydown', function(e) {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); cardHeader.click(); }
  });

  // Toggle fix section
  const fixToggle = card.querySelector('.fix-toggle');
  if (fixToggle) {
    const fixContent = card.querySelector('.fix-content');
    const fixChev    = card.querySelector('.fix-chevron');
    fixToggle.addEventListener('click', function(e) {
      e.stopPropagation();
      const isOpen = fixContent.classList.toggle('open');
      fixChev.classList.toggle('open', isOpen);
    });
    fixToggle.addEventListener('keydown', function(e) {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fixToggle.click(); }
    });
  }

  return card;
}

// ── Render all cards ─────────────────────────────────────────────
const container = document.getElementById('cards-container');

const sortedChecks = CHECKS.slice().sort(function(a,b) {
  const sevOrder = {Critical:0,High:1,Medium:2,Low:3,Informational:4};
  const resOrder = {Fail:0,Warning:1,Pass:2,Info:3,NotApplicable:4};
  const rDiff = (resOrder[a.result] ?? 9) - (resOrder[b.result] ?? 9);
  if (rDiff !== 0) return rDiff;
  const sDiff = (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9);
  if (sDiff !== 0) return sDiff;
  return a.checkId.localeCompare(b.checkId);
});

const cardMap = {};
sortedChecks.forEach(function(check) {
  const card = createCard(check);
  container.appendChild(card);
  cardMap[check.checkId] = card;
});

// ── Top 5 ────────────────────────────────────────────────────────
function renderTop5() {
  const actionable = CHECKS.filter(function(c){ return ['Fail','Warning'].includes(c.result) && !isAccepted(c.checkId); });
  const resOrder   = {Fail:0, Warning:1};
  const top5 = actionable.slice().sort(function(a,b) {
    const rDiff = (resOrder[a.result] ?? 9) - (resOrder[b.result] ?? 9);
    if (rDiff !== 0) return rDiff;
    return (SEV_WEIGHT[b.severity]||0) - (SEV_WEIGHT[a.severity]||0);
  }).slice(0,5);

  const body = document.getElementById('top5-body');
  body.innerHTML = '';
  if (!top5.length) {
    const p = document.createElement('div');
    p.style.cssText = 'padding:16px;color:var(--text2);font-size:13px';
    p.textContent = 'No failing or warning checks.';
    body.appendChild(p);
    return;
  }
  top5.forEach(function(check, i) {
    const rbClass = 'rb-' + slug(check.result);
    const row = document.createElement('div');
    row.className = 'top5-row';
    row.innerHTML =
      '<div class="top5-rank">' + (i+1) + '</div>' +
      '<div>' +
        '<div class="top5-id">' + esc(check.checkId) + '</div>' +
        '<div class="top5-name">' + esc(check.name) + '</div>' +
      '</div>' +
      '<div class="top5-finding">' + fmtFinding(check.finding) + '</div>' +
      '<div style="display:flex;flex-direction:column;align-items:flex-end;gap:4px">' +
        '<span class="result-badge ' + rbClass + '">' + esc(check.result.toUpperCase()) + '</span>' +
        '<span class="sev-pill sev-' + slug(sevOf(check.severity)) + '">' + esc(sevOf(check.severity).toUpperCase()) + '</span>' +
      '</div>';
    row.addEventListener('click', function() {
      const card = cardMap[check.checkId];
      if (!card) return;
      const body = card.querySelector('.card-body');
      const chev = card.querySelector('.card-chevron');
      if (!body.classList.contains('open')) {
        body.classList.add('open');
        chev.classList.add('open');
      }
      card.scrollIntoView({behavior:'smooth', block:'center'});
    });
    body.appendChild(row);
  });
}

document.getElementById('top5-toggle').addEventListener('click', function() {
  const body = document.getElementById('top5-body');
  const chev = document.getElementById('top5-chevron');
  const isOpen = body.classList.toggle('open');
  chev.classList.toggle('open', isOpen);
});

// ── Controls Reference ───────────────────────────────────────────
function renderControlsRef() {
  const el = document.getElementById('ctrl-ref');
  if (!el) return;

  const byCategory = {};
  CHECKS.forEach(function(c) {
    if (!byCategory[c.category]) byCategory[c.category] = [];
    byCategory[c.category].push(c);
  });

  let html = '';
  CONTROLS_CATEGORIES.forEach(function(cat) {
    const sevOrder = {Critical:0,High:1,Medium:2,Low:3,Informational:4};
    const resOrder = {Fail:0,Warning:1,Pass:2,Info:3,NotApplicable:4};
    const checks = (byCategory[cat.id] || []).slice().sort(function(a,b) {
      const rDiff = (resOrder[a.result] ?? 9) - (resOrder[b.result] ?? 9);
      if (rDiff !== 0) return rDiff;
      const sDiff = (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9);
      if (sDiff !== 0) return sDiff;
      return a.checkId.localeCompare(b.checkId);
    });
    if (!checks.length) return;
    html += '<div class="ctrl-section">';
    html += '<div class="ctrl-section-header"><span class="cat-badge ' + cat.cls + '">' + esc(cat.id) + '</span><span>' + esc(cat.label) + '</span></div>';
    html += '<table class="ctrl-table"><thead><tr><th>ID</th><th>Name</th><th>Severity</th><th>What It Checks</th><th>Result</th><th>Docs</th></tr></thead><tbody>';
    checks.forEach(function(c) {
      const accepted = isAccepted(c.checkId);
      const hasError = !!c.error;
      // hasError wins over accepted - see the matching note in createCard().
      const resultDisplay = hasError ? 'Error' : (accepted ? 'Accepted' : c.result);
      const rbClass = 'rb-' + (hasError ? 'error' : (accepted ? 'accepted' : slug(c.result)));
      const desc = CONTROLS_META[c.checkId] || c.name;
      html += '<tr class="ctrl-row" data-checkid="' + esc(c.checkId) + '" title="Click to jump to check card">';
      html += '<td class="ctrl-id">' + esc(c.checkId) + '</td>';
      html += '<td class="ctrl-name">' + esc(c.name) + '</td>';
      html += '<td><span class="sev-pill sev-' + slug(sevOf(c.severity)) + '">' + esc(sevOf(c.severity).toUpperCase()) + '</span></td>';
      html += '<td class="ctrl-desc">' + esc(desc) + '</td>';
      html += '<td><span class="result-badge ' + rbClass + '">' + esc(resultDisplay.toUpperCase()) + '</span></td>';
      html += '<td>' + (c.referenceUrl ? '<a class="ctrl-doc-link" href="' + safeHref(c.referenceUrl) + '" target="_blank" rel="noopener">&#x1F4D6;</a>' : '') + '</td>';
      html += '</tr>';
    });
    html += '</tbody></table></div>';
  });

  el.innerHTML = html || '<p style="padding:24px;color:var(--text2)">No check data available.</p>';

  el.querySelectorAll('.ctrl-doc-link').forEach(function(link) {
    link.addEventListener('click', function(e) { e.stopPropagation(); });
  });

  el.querySelectorAll('.ctrl-row').forEach(function(row) {
    row.addEventListener('click', function() {
      const checkId = this.dataset.checkid;
      switchToTab('All');
      const card = cardMap[checkId];
      if (card) { card.scrollIntoView({ behavior: 'smooth', block: 'center' }); }
    });
  });
}

function switchToTab(tabName) {
  document.querySelectorAll('.tab').forEach(function(t) { t.classList.remove('active'); });
  const target = document.querySelector('.tab[data-tab="' + tabName + '"]');
  if (target) target.classList.add('active');
  activeTab = tabName;
  applyFilters();
}

// ── Filtering ────────────────────────────────────────────────────
let activeTab = 'All';
const allCards = Array.from(container.querySelectorAll('.card'));
const ctrlRef  = document.getElementById('ctrl-ref');

function applyFilters() {
  const isControls = activeTab === 'Controls';
  const isTop5     = activeTab === 'Top5';
  const isCards    = !isControls && !isTop5;
  const search     = document.getElementById('search').value.toLowerCase();
  const sevFilter  = document.getElementById('sev-filter').value;
  const resFilter  = document.getElementById('result-filter').value;

  document.getElementById('top5-section').style.display = (activeTab === 'All' || isTop5) ? '' : 'none';
  document.getElementById('cards-container').style.display = isCards ? '' : 'none';
  document.getElementById('no-results').style.display = 'none';
  document.querySelector('.filters').style.display = isCards ? '' : 'none';

  if (isControls) {
    ctrlRef.classList.add('visible');
    document.getElementById('result-count').textContent = CHECKS.length + ' controls';
    updateTabCounts();
    return;
  }
  ctrlRef.classList.remove('visible');

  if (isTop5) {
    const top5body = document.getElementById('top5-body');
    const top5chev = document.getElementById('top5-chevron');
    if (top5body && !top5body.classList.contains('open')) {
      top5body.classList.add('open');
      if (top5chev) top5chev.classList.add('open');
    }
    updateTabCounts();
    return;
  }

  let visible = 0, inScopeTotal = 0;
  allCards.forEach(function(card) {
    const cat      = card.dataset.category;
    const result   = card.dataset.result;
    const isErr    = card.dataset.error === '1';
    const sev      = card.dataset.sev;
    const sText    = card.dataset.search || '';
    const isAcc    = card.dataset.accepted === '1';

    // Accepted cards move out of All/MDO/EXO/Teams and into the Accepted tab.
    let inScope;
    if (activeTab === 'Accepted') {
      inScope = isAcc;
    } else {
      inScope = !isAcc;
      if (inScope && activeTab === 'MDO')        inScope = cat === 'MDO';
      else if (inScope && activeTab === 'EXO')   inScope = cat === 'EXO';
      else if (inScope && activeTab === 'Teams') inScope = cat === 'Teams';
    }
    if (inScope) inScopeTotal++;

    let show = inScope;
    if (show && sevFilter) show = sev === sevFilter;
    // Error is its own bucket, mutually exclusive with every Result-based option, matching the
    // ERROR badge on the card itself and the summary/donut counts above.
    if (show && resFilter) show = resFilter === 'Error' ? isErr : (result === resFilter && !isErr);
    if (show && search)    show = sText.includes(search);

    card.style.display = show ? '' : 'none';
    if (show) visible++;
  });

  document.getElementById('no-results').style.display = visible === 0 ? '' : 'none';
  document.getElementById('result-count').textContent = 'Showing ' + visible + ' of ' + inScopeTotal + ' checks';
  updateTabCounts();
}

function updateTabCounts() {
  const counts = {All:0, MDO:0, EXO:0, Teams:0, Accepted:0};
  allCards.forEach(function(card) {
    if (card.dataset.accepted === '1') { counts.Accepted++; return; }
    counts.All++;
    counts[card.dataset.category] = (counts[card.dataset.category] || 0) + 1;
  });
  document.getElementById('tc-all').textContent      = counts.All;
  document.getElementById('tc-accepted').textContent = counts.Accepted || 0;
  document.getElementById('tc-mdo').textContent      = counts.MDO || 0;
  document.getElementById('tc-exo').textContent      = counts.EXO || 0;
  document.getElementById('tc-teams').textContent    = counts.Teams || 0;
  document.getElementById('tc-controls').textContent = CHECKS.length;
}

document.querySelectorAll('.tab').forEach(function(tab) {
  tab.addEventListener('click', function() {
    document.querySelectorAll('.tab').forEach(function(t){ t.classList.remove('active'); });
    this.classList.add('active');
    activeTab = this.dataset.tab;
    applyFilters();
  });
});
document.getElementById('search').addEventListener('input', applyFilters);
document.getElementById('sev-filter').addEventListener('change', applyFilters);
document.getElementById('result-filter').addEventListener('change', applyFilters);
document.getElementById('print-btn').addEventListener('click', function() { window.print(); });

// ── Collapse / Expand all ────────────────────────────────────────
let allExpanded = false;
document.getElementById('btn-collapse-all').addEventListener('click', function() {
  allExpanded = !allExpanded;
  this.textContent = allExpanded ? 'Collapse All' : 'Expand All';
  allCards.forEach(function(card) {
    if (card.style.display === 'none') return;
    const body   = card.querySelector('.card-body');
    const chevron = card.querySelector('.card-chevron');
    const header  = card.querySelector('.card-header');
    body.classList.toggle('open', allExpanded);
    chevron.classList.toggle('open', allExpanded);
    if (header) header.setAttribute('aria-expanded', allExpanded);
    if (allExpanded) {
      const isFailWarn = ['Fail','Warning'].includes(card.dataset.result);
      if ((isFailWarn || card.dataset.error === '1') && !card.dataset.fixOpened) {
        card.dataset.fixOpened = '1';
        const fixContent = card.querySelector('.fix-content');
        const fixChev    = card.querySelector('.fix-chevron');
        if (fixContent && !fixContent.classList.contains('open')) {
          fixContent.classList.add('open');
          if (fixChev) fixChev.classList.add('open');
        }
      }
    }
  });
});

// ── Accept risk ──────────────────────────────────────────────────
let pendingCheckId = null;

document.addEventListener('click', function(e) {
  const acceptBtn = e.target.closest('.btn-accept');
  if (acceptBtn) {
    pendingCheckId = acceptBtn.dataset.checkid;
    document.getElementById('modal-desc').textContent = 'Accepting risk for ' + pendingCheckId + '. Provide a business justification.';
    document.getElementById('modal-text').value = '';
    document.getElementById('modal-confirm').disabled = true;
    document.getElementById('modal-overlay').classList.add('open');
    setTimeout(function(){ document.getElementById('modal-text').focus(); }, 50);
  }

  const undoBtn = e.target.closest('.btn-undo');
  if (undoBtn) {
    const checkId = undoBtn.dataset.checkid;
    clearAccepted(checkId);
    rebuildCard(checkId);
    updateTabCounts();
    recalcScore();
    renderTop5();
    applyFilters();
  }
});

document.getElementById('modal-text').addEventListener('input', function() {
  document.getElementById('modal-confirm').disabled = this.value.trim().length === 0;
});

document.getElementById('modal-cancel').addEventListener('click', function() {
  document.getElementById('modal-overlay').classList.remove('open');
  pendingCheckId = null;
});

document.getElementById('modal-confirm').addEventListener('click', function() {
  if (!pendingCheckId) return;
  const just = document.getElementById('modal-text').value.trim();
  setAccepted(pendingCheckId, just);
  document.getElementById('modal-overlay').classList.remove('open');
  rebuildCard(pendingCheckId);
  updateTabCounts();
  recalcScore();
  renderTop5();
  applyFilters();
  pendingCheckId = null;
});

document.getElementById('modal-overlay').addEventListener('click', function(e) {
  if (e.target === this) { document.getElementById('modal-cancel').click(); }
});

function rebuildCard(checkId) {
  const check = CHECKS.find(function(c){ return c.checkId === checkId; });
  if (!check) return;
  const oldCard = cardMap[checkId];
  if (!oldCard) return;
  const newCard = createCard(check);
  oldCard.parentNode.replaceChild(newCard, oldCard);
  cardMap[checkId] = newCard;
  const idx = allCards.indexOf(oldCard);
  if (idx !== -1) allCards[idx] = newCard;
}

// ── Init ─────────────────────────────────────────────────────────
(function() {
  const LS_SCORE_KEY = 'MET_score_' + TENANT_ID;
  const prev = lsGet(LS_SCORE_KEY);
  if (prev !== null) {
    const delta = INITIAL_SCORE - parseInt(prev, 10);
    if (delta !== 0) {
      const el = document.getElementById('score-delta');
      if (el) {
        el.textContent = (delta > 0 ? '+' : '') + delta;
        el.className = 'score-delta ' + (delta > 0 ? 'delta-up' : 'delta-down');
      }
    }
  }
  lsSet(LS_SCORE_KEY, INITIAL_SCORE);
})();
renderTop5();
renderControlsRef();
applyFilters();
recalcScore();
// Button label reflects initial state (all collapsed, so button offers "Expand All")
document.getElementById('btn-collapse-all').textContent = 'Expand All';
})();
</script>
</body>
</html>
"@

            if ($OutputPath) {
                $dest = $resolvedHtmlPath

                $html | Set-Content -Path $dest -Encoding UTF8
                Write-Verbose "HTML report written to $dest"
                if ($assessmentOutputFolder -and -not $assessmentFolderAnnounced) {
                  Write-Verbose "Assessment output folder: $assessmentOutputFolder"
                  $assessmentFolderAnnounced = $true
                }

                try { Start-Process $dest } catch { Write-Verbose "Could not auto-open browser: $_" }
            } else {
                $html
            }
        }
    }
}
