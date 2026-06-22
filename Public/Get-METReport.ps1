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
          # Best-effort discovery only; continue with additional fallbacks.
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
                $w = Get-METCheckWeight -Severity $r.Severity
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
                    $w = Get-METCheckWeight -Severity $r.Severity
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

        $summary = @{
            Pass          = ($allResults | Where-Object Result -eq 'Pass').Count
            Fail          = ($allResults | Where-Object Result -eq 'Fail').Count
            Warning       = ($allResults | Where-Object Result -eq 'Warning').Count
            NotApplicable = ($allResults | Where-Object Result -eq 'NotApplicable').Count
            Error         = ($allResults | Where-Object { $_.Error }).Count
        }

        # ── Console ──────────────────────────────────────────────────────────
        if ($Format -in 'Console','All') {
            Write-Host ''
            Write-Host '══════════════════════════════════════════════════════' -ForegroundColor Cyan
            Write-Host '  MET — Security Posture Scanner for MDO, EXO and Teams' -ForegroundColor Cyan
            if ($effectiveTenantName) { Write-Host "  Tenant: $effectiveTenantName" -ForegroundColor Gray }
            Write-Host "  Run:    $($runTimestampUtc.ToString('yyyy-MM-dd HH:mm')) UTC" -ForegroundColor Gray
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

            Write-Host "  Pass: $($summary.Pass)  Fail: $($summary.Fail)  Warning: $($summary.Warning)  N/A: $($summary.NotApplicable)  Error: $($summary.Error)"
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
            $METVersion = (Get-Module MET -ErrorAction SilentlyContinue)?.Version.ToString() ?? '0.2.0'

            $jsonObj = [ordered]@{
                tenant         = $effectiveTenantName
                runTimestamp   = $runTimestampUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
                METVersion    = $METVersion
                postureScore   = $overallScore
                categoryScores = $categoryScores
                summary        = $summary
                checks         = $allResults | ForEach-Object {
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
                        timestamp      = $_.Timestamp.ToString('yyyy-MM-ddTHH:mm:ssZ')
                        error          = $_.Error
                    }
                }
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
            $METVersion  = (Get-Module MET -ErrorAction SilentlyContinue)?.Version.ToString() ?? '0.2.0'
            $runTimestamp = $runTimestampUtc.ToString('yyyy-MM-dd HH:mm') + ' UTC'
            $tenantId     = if ($effectiveTenantName) { $effectiveTenantName } else { 'unknown' }
            $tenantIdJson = $tenantId | ConvertTo-Json -Compress

            $checksJson = ($allResults | ForEach-Object {
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
                    timestamp      = $_.Timestamp.ToString('yyyy-MM-ddTHH:mm:ssZ')
                    error          = $_.Error
                }
            }) | ConvertTo-Json -Depth 5 -Compress

            # Escape </script> so embedded JSON cannot break the script block
            $tenantIdJson  = $tenantIdJson  -replace '</script>', '<\/script>'
            $checksJson    = $checksJson    -replace '</script>', '<\/script>'
            $catScoresJson = ($categoryScores | ConvertTo-Json -Compress) -replace '</script>', '<\/script>'

            $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MET Report — $([System.Security.SecurityElement]::Escape($tenantId))</title>
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
.header{background:var(--surface);border-bottom:1px solid var(--border);padding:16px 20px 16px 20px;box-shadow:var(--shadow);border-left:4px solid var(--accent-mdo)}
.header-title{font-size:20px;font-weight:600;margin-bottom:3px;letter-spacing:-.01em}
.header-meta{font-size:12px;color:var(--text2)}

/* ── Score banner ────────────────────────────────────────────────── */
.score-banner{background:var(--surface);border-bottom:1px solid var(--border);padding:16px 24px 16px 20px;display:flex;align-items:center;gap:32px;flex-wrap:wrap;border-left:4px solid var(--border);transition:border-left-color .3s}
.score-banner[data-band="excellent"],.score-banner[data-band="good"]{border-left-color:var(--result-pass)}
.score-banner[data-band="fair"]{border-left-color:var(--sev-medium)}
.score-banner[data-band="poor"]{border-left-color:var(--sev-high)}
.score-banner[data-band="critical"]{border-left-color:var(--result-fail)}
.score-main{display:flex;flex-direction:column;align-items:flex-start;gap:4px}
.score-label{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:var(--text2)}
.score-row{display:flex;align-items:baseline;gap:8px}
.score-number{font-size:52px;font-weight:700;line-height:1;letter-spacing:-2px}
.score-delta{font-size:16px;font-weight:700;line-height:1}
.delta-up{color:var(--result-pass)}
.delta-down{color:var(--result-fail)}
.score-progress-track{width:180px;height:6px;background:var(--border);border-radius:3px;overflow:hidden;margin-top:4px}
.score-progress-bar{height:100%;border-radius:3px;transition:width .4s ease,background .3s}
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
.score-cats{display:flex;gap:12px;flex-wrap:wrap;align-items:center}
.cat-badge{padding:4px 12px;border-radius:10px;font-size:13px;font-weight:600;color:#fff}
.cat-mdo{background:var(--accent-mdo)}
.cat-exo{background:var(--accent-exo)}
.cat-teams{background:var(--accent-teams)}
.score-summary{display:flex;gap:16px;flex-wrap:wrap;font-size:13px;padding-left:16px;border-left:1px solid var(--border)}
.summary-item{display:flex;flex-direction:column;align-items:center;gap:2px}
.summary-count{font-size:22px;font-weight:700}
.summary-label{font-size:11px;color:var(--text2);text-transform:uppercase;letter-spacing:.04em}
.s-pass{color:var(--result-pass)}
.s-fail{color:var(--result-fail)}
.s-warn{color:var(--result-warn)}
.s-na{color:var(--result-na)}
.s-err{color:var(--sev-critical)}

/* ── Toolbar ─────────────────────────────────────────────────────── */
.toolbar{background:var(--surface);border-bottom:1px solid var(--border);padding:0 24px;display:flex;align-items:center;gap:0;flex-wrap:wrap}
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
.card-header{display:flex;align-items:center;gap:10px;padding:10px 14px;cursor:pointer;user-select:none}
.card-header:hover{background:var(--surface2)}
.sev-pill{font-size:11px;font-weight:700;padding:2px 7px;border-radius:8px;color:#fff;white-space:nowrap;flex-shrink:0}
.sev-critical{background:var(--sev-critical)}
.sev-high{background:var(--sev-high)}
.sev-medium{background:var(--sev-medium)}
.sev-low{background:var(--sev-low)}
.sev-informational{background:var(--sev-info)}
.card-id{font-size:12px;font-family:monospace;color:var(--text2);flex-shrink:0}
.card-name{font-weight:600;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.result-badge{font-size:12px;font-weight:700;padding:2px 8px;border-radius:8px;flex-shrink:0;color:#fff}
.rb-pass{background:var(--result-pass)}
.rb-fail{background:var(--result-fail)}
.rb-warning{background:var(--result-warn)}
.rb-notapplicable,.rb-info{background:var(--result-na)}
.rb-accepted{background:var(--result-accepted)}
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
</style>
</head>
<body>
<div class="header">
  <div class="header-title">MET — Security Posture Scanner for MDO, EXO and Teams</div>
  <div class="header-meta" id="header-meta">
    $([System.Security.SecurityElement]::Escape($(if ($effectiveTenantName) { "Tenant: $effectiveTenantName  ·  " } else { '' })))Run: $runTimestamp  ·  MET v$METVersion
  </div>
</div>

<div class="score-banner" data-band="$(($band).ToLower())" id="score-banner">
  <div class="score-main">
    <div class="score-label">Posture Index</div>
    <div class="score-row">
      <div class="score-number" id="score-number">$overallScore</div>
      <div class="score-delta" id="score-delta"></div>
    </div>
    <div class="score-progress-track">
      <div class="score-progress-bar bar-$(($band).ToLower())" id="score-progress-bar" style="width:$overallScore%"></div>
    </div>
    <div class="score-band-wrap">
      <div class="score-band band-$(($band).ToLower())" id="score-band">$band</div>
      <div class="band-info-icon" tabindex="0" aria-label="Band scale guide">&#x24D8;</div>
      <div class="band-tooltip" id="band-tooltip" role="tooltip"></div>
    </div>
  </div>
  <div class="score-cats" id="score-cats"></div>
  <div class="score-summary">
    <div class="summary-item"><span class="summary-count s-fail" id="sum-fail">$($summary.Fail)</span><span class="summary-label">Fail</span></div>
    <div class="summary-item"><span class="summary-count s-warn" id="sum-warn">$($summary.Warning)</span><span class="summary-label">Warning</span></div>
    <div class="summary-item"><span class="summary-count s-pass" id="sum-pass">$($summary.Pass)</span><span class="summary-label">Pass</span></div>
    <div class="summary-item"><span class="summary-count s-na" id="sum-na">$($summary.NotApplicable)</span><span class="summary-label">N/A</span></div>
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
      <option>Fail</option><option>Warning</option><option>Pass</option><option>NotApplicable</option><option>Info</option>
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
const CAT_SCORES = $catScoresJson;
const TENANT_ID = $tenantIdJson;
const INITIAL_SCORE = $overallScore;
const SEV_WEIGHT = {Critical:40,High:20,Medium:10,Low:5,Informational:0};

const CONTROLS_META = {
  'MET-MDO001': 'Safe Links enabled for email and Office apps; verifies TrackClicks, EnableForInternalSenders, and real-time scanning are configured.',
  'MET-MDO002': 'Safe Attachments enabled with Block or DynamicDelivery action — flags any policy set to Allow.',
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
  'MET-EXO001': 'DMARC record present; policy is quarantine or reject (not none); rua reporting address configured.',
  'MET-EXO002': 'DKIM signing enabled for all accepted domains; key length is at least 2048 bits.',
  'MET-EXO003': 'SPF record present; no use of +all (pass-all); within the 10 DNS lookup limit.',
  'MET-EXO004': 'Default quarantine policies reviewed; user notification enabled; no AdminOnlyAccessPolicy on high-confidence phish quarantine.',
  'MET-EXO005': 'Stale allow entries older than 90 days; overly broad wildcard allows; ratio of allows to blocks.',
  'MET-EXO006': 'User submission mailbox configured and reporting to Microsoft enabled.',
  'MET-EXO007': 'Transport rules that bypass spam filtering (SCLJunk=-1) or disable Safe Links — informational audit.',
  'MET-EXO008': 'QuarantineRetentionPeriod is at least 30 days in all anti-spam policies (default is 15; Standard/Strict recommend 30).',
  'MET-Teams001': 'EnableSafeLinksForTeams enabled in Safe Links policies that cover Teams users.',
  'MET-Teams002': 'Global EnableATPForSPOTeamsODB enabled; EnableSafeAttachmentsForTeams enabled in at least one policy.',
  'MET-Teams003': 'External access settings, anonymous join policy, and lobby bypass settings reviewed for security posture.',
  'MET-Teams004': 'TeamsProtectionPolicy ZAP enabled; malware and high-confidence phish quarantine tags set to AdminOnlyAccessPolicy.',
  'MET-Teams005': 'ReportTeamsMsgEnabled in submission policy and AllowSecurityEndUserReporting in Teams messaging policy.'
};

const CONTROLS_CATEGORIES = [
  { id: 'MDO',   label: 'Microsoft Defender for Office 365', cls: 'cat-mdo'   },
  { id: 'EXO',   label: 'Exchange Online / Email Authentication', cls: 'cat-exo'   },
  { id: 'Teams', label: 'Microsoft Teams Protection',         cls: 'cat-teams' }
];

// ── localStorage helpers ─────────────────────────────────────────
function lsKey(checkId){ return 'MET_accepted_' + TENANT_ID + '_' + checkId; }
function isAccepted(checkId){ return !!localStorage.getItem(lsKey(checkId)); }
function getJustification(checkId){ return localStorage.getItem(lsKey(checkId)); }
function setAccepted(checkId, justification){ localStorage.setItem(lsKey(checkId), justification || 'Accepted'); }
function clearAccepted(checkId){ localStorage.removeItem(lsKey(checkId)); }

// ── Score calculation ────────────────────────────────────────────
function recalcScore() {
  let wSum = 0, wTotal = 0;
  CHECKS.forEach(function(c) {
    if (!['Pass','Fail','Warning'].includes(c.result)) return;
    if (c.score === null || c.score === undefined) return;
    if (isAccepted(c.checkId)) return;
    const w = SEV_WEIGHT[c.severity] || 0;
    wSum  += c.score * w;
    wTotal += w * 100;
  });
  const score = wTotal > 0 ? Math.round((wSum / wTotal) * 100) : 0;
  const band = score >= 95 ? 'Excellent' : score >= 80 ? 'Good' : score >= 60 ? 'Fair' : score >= 40 ? 'Poor' : 'Critical';
  document.getElementById('score-number').textContent = score;
  const bandEl = document.getElementById('score-band');
  bandEl.textContent = band;
  bandEl.className = 'score-band band-' + band.toLowerCase();
  const banner = document.getElementById('score-banner');
  if (banner) banner.dataset.band = band.toLowerCase();
  const bar = document.getElementById('score-progress-bar');
  if (bar) { bar.style.width = score + '%'; bar.className = 'score-progress-bar bar-' + band.toLowerCase(); }
  renderBandTooltip(band);
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

// ── Category score badges ────────────────────────────────────────
function renderCatScores() {
  const el = document.getElementById('score-cats');
  el.innerHTML = '';
  [['MDO','cat-mdo'],['EXO','cat-exo'],['Teams','cat-teams']].forEach(function(pair) {
    const cat = pair[0], cls = pair[1];
    const val = CAT_SCORES[cat];
    if (val === null || val === undefined) return;
    const badge = document.createElement('div');
    badge.className = 'cat-badge ' + cls;
    badge.textContent = cat + ': ' + val;
    el.appendChild(badge);
  });
}

// ── Escape HTML ──────────────────────────────────────────────────
function esc(s) {
  if (!s) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
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
function fmtFinding(s) {
  if (!s) return '';
  var normalized = s.replace(/·|–|—|―/g, '-');
  var lines = normalized.split('\n').filter(function(l){ return l.trim(); });

  if (lines.length <= 1) {
    var parts = splitPipe(normalized);
    var text = parts[0], code = parts[1];
    var issues = text.split(/;\s*/).filter(function(i){ return i.trim(); });
    var issuesHtml = issues.length <= 1 ? esc(text) :
      '<ul class="finding-list">' + issues.map(function(i){ return '<li>' + esc(i.trim()) + '</li>'; }).join('') + '</ul>';
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
        issues.map(function(i){ return '<li>' + esc(i.trim()) + '</li>'; }).join('') +
        '</ul>' : '') +
      codeBlockHtml(code) +
      '</div>';
  }).join('');
}
function safeHref(url) {
  if (!url) return '#';
  try { const u = new URL(url); return (u.protocol === 'https:' || u.protocol === 'http:') ? url : '#'; }
  catch { return '#'; }
}

// ── Build recommendation as list if multi-line ───────────────────
function buildRecommendation(rec) {
  if (!rec) return '';
  const lines = rec.split(/\n/).map(function(l){ return l.trim(); }).filter(Boolean);
  if (lines.length <= 1) return '<p>' + esc(rec) + '</p>';
  return '<ol>' + lines.map(function(l){ return '<li>' + esc(l.replace(/^\d+\.\s*/, '')) + '</li>'; }).join('') + '</ol>';
}

// ── Render a single card ─────────────────────────────────────────
function createCard(check) {
  const accepted   = isAccepted(check.checkId);
  const isFailWarn = ['Fail','Warning'].includes(check.result);
  const showFix    = isFailWarn || !!check.error;
  const isPass     = check.result === 'Pass';
  const resultDisplay = accepted ? 'Accepted' : check.result;
  const rbClass    = 'rb-' + (accepted ? 'accepted' : check.result.toLowerCase());
  const startOpen  = false;

  const card = document.createElement('div');
  card.className = 'card';
  card.dataset.checkId  = check.checkId;
  card.dataset.category = check.category;
  card.dataset.result   = check.result;
  card.dataset.sev      = check.severity;
  card.dataset.accepted = accepted ? '1' : '0';
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
      '<span class="sev-pill sev-' + check.severity.toLowerCase() + '">' + esc(check.severity.toUpperCase()) + '</span>' +
      '<span class="card-id">' + esc(check.checkId) + '</span>' +
      '<span class="card-name">' + esc(check.name) + '</span>' +
      '<span class="result-badge ' + rbClass + '">' + esc(resultDisplay.toUpperCase()) + '</span>' +
      '<span class="card-chevron' + (startOpen ? ' open' : '') + '">&#x25BC;</span>' +
    '</div>' +
    '<div class="card-body' + bodyOpen + '">' +
      '<div class="card-field"><span class="field-label">Affected Object</span><span class="field-value">' + esc(check.affectedObject) + '</span></div>' +
      '<div class="card-field"><span class="field-label">Finding</span><span class="field-value">' + fmtFinding(check.finding) + '</span></div>' +
      fixHtml +
      '<div class="card-actions">' + actionsHtml + '</div>' +
    '</div>';

  // Toggle card body; auto-open fix section on first expand of Fail/Warning
  card.querySelector('.card-header').addEventListener('click', function() {
    const body    = card.querySelector('.card-body');
    const chevron = card.querySelector('.card-chevron');
    const isOpen  = body.classList.toggle('open');
    chevron.classList.toggle('open', isOpen);
    this.setAttribute('aria-expanded', isOpen);
    if (isOpen && isFailWarn && !card.dataset.fixOpened) {
      card.dataset.fixOpened = '1';
      const fixContent = card.querySelector('.fix-content');
      const fixChev    = card.querySelector('.fix-chevron');
      if (fixContent && !fixContent.classList.contains('open')) {
        fixContent.classList.add('open');
        if (fixChev) fixChev.classList.add('open');
      }
    }
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
    const rbClass = 'rb-' + check.result.toLowerCase();
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
        '<span class="sev-pill sev-' + check.severity.toLowerCase() + '">' + esc(check.severity.toUpperCase()) + '</span>' +
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
      const resultDisplay = accepted ? 'Accepted' : c.result;
      const rbClass = 'rb-' + (accepted ? 'accepted' : c.result.toLowerCase());
      const desc = CONTROLS_META[c.checkId] || c.name;
      html += '<tr class="ctrl-row" data-checkid="' + esc(c.checkId) + '" title="Click to jump to check card">';
      html += '<td class="ctrl-id">' + esc(c.checkId) + '</td>';
      html += '<td class="ctrl-name">' + esc(c.name) + '</td>';
      html += '<td><span class="sev-pill sev-' + c.severity.toLowerCase() + '">' + esc(c.severity.toUpperCase()) + '</span></td>';
      html += '<td class="ctrl-desc">' + esc(desc) + '</td>';
      html += '<td><span class="result-badge ' + rbClass + '">' + esc(resultDisplay.toUpperCase()) + '</span></td>';
      html += '<td>' + (c.referenceUrl ? '<a href="' + safeHref(c.referenceUrl) + '" target="_blank" rel="noopener" onclick="event.stopPropagation()">&#x1F4D6;</a>' : '') + '</td>';
      html += '</tr>';
    });
    html += '</tbody></table></div>';
  });

  el.innerHTML = html || '<p style="padding:24px;color:var(--text2)">No check data available.</p>';

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

  let visible = 0;
  allCards.forEach(function(card) {
    const cat    = card.dataset.category;
    const result = card.dataset.result;
    const sev    = card.dataset.sev;
    const sText  = card.dataset.search || '';

    let show = true;
    if (activeTab === 'MDO')        show = cat === 'MDO';
    else if (activeTab === 'EXO')   show = cat === 'EXO';
    else if (activeTab === 'Teams') show = cat === 'Teams';

    if (show && sevFilter) show = sev === sevFilter;
    if (show && resFilter) show = result === resFilter;
    if (show && search)    show = sText.includes(search);

    card.style.display = show ? '' : 'none';
    if (show) visible++;
  });

  document.getElementById('no-results').style.display = visible === 0 ? '' : 'none';
  document.getElementById('result-count').textContent = 'Showing ' + visible + ' of ' + allCards.length + ' checks';
  updateTabCounts();
}

function updateTabCounts() {
  const counts = {All:0, MDO:0, EXO:0, Teams:0};
  allCards.forEach(function(card) {
    counts.All++;
    counts[card.dataset.category] = (counts[card.dataset.category] || 0) + 1;
  });
  document.getElementById('tc-all').textContent      = counts.All;
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
      if (isFailWarn && !card.dataset.fixOpened) {
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
}

// ── Init ─────────────────────────────────────────────────────────
(function() {
  const LS_SCORE_KEY = 'MET_score_' + TENANT_ID;
  const prev = localStorage.getItem(LS_SCORE_KEY);
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
  localStorage.setItem(LS_SCORE_KEY, INITIAL_SCORE);
})();
renderCatScores();
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
