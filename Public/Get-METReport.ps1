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
    <#
    .SYNOPSIS
        Formats MET check results as a console summary, JSON export, or self-contained HTML report.

    .DESCRIPTION
        Takes the result objects produced by Invoke-METAssessment (or re-hydrated by
        Import-METReport) and renders them in one or more formats: a coloured console summary
        with a posture score and a Fail/Warning table, a machine-readable JSON document suitable
        for SIEM ingestion or a CI gate, or a single self-contained HTML file (all CSS/JS
        inlined, no external dependencies) that auto-opens in the default browser.

        Every result carries a per-run tenant provenance stamp. Get-METReport refuses to render
        a result set that spans more than one tenant - a mixed set would otherwise be labelled
        with one customer's identity while carrying another's configuration, which is exactly
        the cross-customer exposure the provenance stamp exists to catch. When -TenantName is
        not given, the tenant label is inferred first from that provenance, then from the live
        Connect-METSession state.

    .PARAMETER InputObject
        The check result objects to report on, typically the output of Invoke-METAssessment or
        Import-METReport. Accepts pipeline input, so `$results | Get-METReport` is the normal
        usage; not Mandatory, because a mandatory pipeline parameter would prompt interactively
        on an empty pipeline and hang a CI process instead of failing it.

    .PARAMETER Format
        Which report format(s) to produce: Console (default; writes a summary to the host and
        returns nothing), JSON, HTML, or All (writes both JSON and HTML). HTML and All require
        -OutputPath, since the HTML report is too long to usefully write to the console.

    .PARAMETER OutputPath
        Where to write the report file(s), for -Format JSON, HTML, or All. For a single format
        (JSON or HTML), pass a file path with an extension to write exactly there, or a
        directory (or an extensionless path) to have the default filename (MET-report.json /
        MET-report.html) written inside a timestamped <run>-<tenant> subfolder created under
        it - grouping runs is useful for a directory, but a filename you typed is written
        exactly as given, with no subfolder inserted underneath it. For -Format All, pass a
        directory - both files are written into a timestamped subfolder under it. Ignored,
        with a warning, when -Format is Console.

    .PARAMETER TenantName
        Overrides the tenant label shown in the console header, JSON `tenant` field, and HTML
        report header. When omitted, the label is inferred from the results' own provenance
        metadata, falling back to the live Connect-METSession state if no provenance is present.

    .PARAMETER NoLaunch
        Suppresses automatically opening the generated HTML report in the default browser.
        Has no effect for -Format Console or -Format JSON, which never auto-launch anything.

    .PARAMETER PassThru
        Returns a System.IO.FileInfo object for each report file actually written to disk - one
        for JSON and/or one for HTML, whichever formats were written with -OutputPath. Returns
        nothing for -Format Console, and nothing for -Format JSON when -OutputPath is not
        supplied, because no file is written to disk in either case (JSON without -OutputPath
        instead emits the report JSON text itself to the pipeline, independently of -PassThru).

    .OUTPUTS
        None by default. With -PassThru, System.IO.FileInfo[] - one object per report file
        written to disk this call, in the order written (JSON before HTML for -Format All);
        an empty array if -PassThru was passed but no format that writes a file actually did
        (-Format Console, or -Format JSON without -OutputPath).

    .EXAMPLE
        $results | Get-METReport

        Prints the default console summary: overall posture score, per-category breakdown,
        a Fail/Warning table, and a Pass count - the quickest way to review a run interactively.

    .EXAMPLE
        $results | Get-METReport -Format HTML -OutputPath ./assessments

        Writes the interactive, self-contained HTML report under ./assessments and opens it in
        the default browser - the report an analyst hands to a customer or keeps for review.

    .EXAMPLE
        $results | Get-METReport -Format JSON -OutputPath ./assessments

        Writes the machine-readable JSON report under ./assessments, suitable for SIEM ingestion
        or a CI/CD gate that inspects postureScore or individual check results.

    .EXAMPLE
        $results | Get-METReport -Format All -OutputPath ./assessments/contoso-2026-06-01/

        Writes both the JSON and HTML reports into one directory in a single call - the pattern
        used for a per-customer, per-run assessment archive.

    .EXAMPLE
        $written = $results | Get-METReport -Format JSON -OutputPath ./assessments -PassThru
        $written.FullName

        Captures the FileInfo object(s) for whatever was actually written to disk, to chain into
        further automation (e.g. uploading the file, or reading its path back for logging)
        without re-deriving the output path yourself.
    #>
    [CmdletBinding(PositionalBinding = $false)]
    param(
        # Not Mandatory: a mandatory pipeline parameter prompts interactively when the
        # pipeline is empty, which hangs a CI process rather than failing it.
        [Parameter(ValueFromPipeline)]
        [AllowEmptyCollection()]
        [PSCustomObject[]] $InputObject = @(),

        [Parameter()]
        [ValidateSet('Console','JSON','HTML','All')]
        [string] $Format = 'Console',

        [Parameter()]
        [string] $OutputPath,

        [Parameter()]
        [string] $TenantName = '',

        [Parameter()]
        [switch] $NoLaunch,

        [Parameter()]
        [switch] $PassThru
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
      $provenanceDisagreesWithLiveSession = $false

      # Every distinct tenant these results were gathered against. More than one means
      # two customers' checks were piped into a single report - it would be labelled with
      # one customer's identity while carrying another's configuration, the same
      # cross-customer exposure the per-run provenance stamp exists to prevent. Refuse it
      # outright rather than pick one label; this holds even when -TenantName is passed,
      # because an explicit label cannot make a mixed result set represent one tenant.
      $provenanceTenants = @($allResults |
        ForEach-Object {
          if ($_.PSObject.Properties['Metadata'] -and $_.Metadata -and $_.Metadata.ContainsKey('METRunTenant')) {
            [string]$_.Metadata['METRunTenant']
          }
        } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Select-Object -Unique)

      if ($provenanceTenants.Count -gt 1) {
        throw "These results were gathered against more than one tenant ($($provenanceTenants -join ', ')). A single report cannot represent multiple tenants - one customer's checks would appear under another customer's identity. Run Get-METReport once per tenant's result set."
      }

      if ([string]::IsNullOrWhiteSpace($effectiveTenantName)) {
        $provenanceTenant = $provenanceTenants | Select-Object -First 1

        $liveTenant = $null
        try {
          $defaultAcceptedDomain = Get-AcceptedDomain -ErrorAction Stop |
            Where-Object { $_.Default -eq $true } |
            Select-Object -First 1

          if ($defaultAcceptedDomain -and $defaultAcceptedDomain.DomainName) {
            $liveTenant = [string]$defaultAcceptedDomain.DomainName
          }
        }
        catch {
          Write-Verbose "Unable to discover default accepted domain: $($_.Exception.Message)"
        }

        if (-not [string]::IsNullOrWhiteSpace($provenanceTenant)) {
          $effectiveTenantName = $provenanceTenant
          if (-not [string]::IsNullOrWhiteSpace($liveTenant) -and $liveTenant -ne $provenanceTenant) {
            $provenanceDisagreesWithLiveSession = $true
            Write-Warning "These results were gathered against '$provenanceTenant', but the live Exchange Online session is connected to '$liveTenant'. The report is labelled '$provenanceTenant'."
          }
        }
        elseif (-not [string]::IsNullOrWhiteSpace($liveTenant)) {
          $effectiveTenantName = $liveTenant
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

      # Imported results (via Import-METReport) carry the authentication of the run that
      # produced them, stamped on Metadata.METRunAuthentication. That record beats the
      # current session's $script:METSessionInfo, which describes whoever this process
      # happens to be connected to right now - a different run entirely. Precedence: imported
      # provenance wins when present; the live session is used only as a fallback. When more
      # than one distinct imported auth block is present (checks from two different runs of
      # the same tenant, piped together), only the first is used to label the report - warn
      # so that choice isn't silent, the same way a tenant mismatch is surfaced above.
      $allImportedAuth = @($allResults |
        ForEach-Object {
          if ($_.PSObject.Properties['Metadata'] -and $_.Metadata -and $_.Metadata.ContainsKey('METRunAuthentication')) {
            $_.Metadata['METRunAuthentication'] | ConvertTo-Json -Compress -Depth 5
          }
        } |
        Where-Object { $_ } |
        Select-Object -Unique)

      if ($allImportedAuth.Count -gt 1) {
        Write-Warning "These results were imported from more than one run with different authentication provenance. The report is labelled with the first run's authentication."
      }

      $importedAuth = @($allResults |
        ForEach-Object {
          if ($_.PSObject.Properties['Metadata'] -and $_.Metadata -and $_.Metadata.ContainsKey('METRunAuthentication')) {
            $_.Metadata['METRunAuthentication']
          }
        } |
        Where-Object { $_ } |
        Select-Object -First 1)

      # Imported results carry the timestamp of the run that produced them, stamped on
      # Metadata.METRunTimestamp - same precedence rule as $importedAuth above: imported
      # provenance wins when present, so re-rendering a saved report doesn't relabel stale
      # findings with the re-render time. Falls back to "now" only when nothing was imported
      # (a live assessment just completed).
      $importedTimestamp = @($allResults |
        ForEach-Object {
          if ($_.PSObject.Properties['Metadata'] -and $_.Metadata -and $_.Metadata.ContainsKey('METRunTimestamp')) {
            $_.Metadata['METRunTimestamp']
          }
        } |
        Where-Object { $_ } |
        Select-Object -First 1)

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

        $band = if (-not $scorable) {
          'None'
        }
        elseif ($overallScore -ge 95) {
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

        $categoryScores = [ordered]@{}
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

        # Imported provenance wins over "now" when present - see $importedTimestamp above.
        $runTimestampUtc = if ($importedTimestamp) {
          [datetime]$importedTimestamp[0]
        } else {
          [datetime]::UtcNow
        }
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
        $writtenFiles = [System.Collections.Generic.List[System.IO.FileInfo]]::new()

        # $wantsHtml covers 'All' too, so this guard is the one that fires for both. The
        # message names whichever format was actually requested - a user who asked for All
        # was previously told '-Format HTML requires -OutputPath', naming a format they
        # never passed, and the later 'All' guard was unreachable dead code.
        if ($wantsHtml -and -not $OutputPath) {
            $PSCmdlet.ThrowTerminatingError(
                [System.Management.Automation.ErrorRecord]::new(
                    [System.ArgumentException]::new(
                        ('-Format {0} requires -OutputPath. The HTML report is a single self-contained file over a thousand lines long; writing it to the console is never what was wanted. Pass -OutputPath <folder>.' -f $Format)),
                    'METOutputPathRequired',
                    [System.Management.Automation.ErrorCategory]::InvalidArgument,
                    $Format))
        }

        if ($OutputPath -and -not ($wantsJson -or $wantsHtml)) {
            Write-Warning '-OutputPath was given but -Format is Console, which writes to the host only. The path is ignored and no directory was created. Use -Format JSON, HTML or All to write files.'
        }

        if ($OutputPath -and ($wantsJson -or $wantsHtml)) {
          $outputIsDirectory = Test-Path -LiteralPath $OutputPath -PathType Container
          $hasExtension = [System.IO.Path]::HasExtension($OutputPath)
          $namesExplicitFile = $hasExtension -and -not $outputIsDirectory -and $Format -ne 'All'

          if ($namesExplicitFile) {
            # C-23: an explicit filename with an extension is written exactly there, with no
            # per-run <timestamp>-<tenant> subfolder inserted underneath it. Grouping runs
            # under a subfolder is genuinely useful applied to a directory, which is a
            # container - applied to a filename the caller typed, it is the command
            # overriding an explicit instruction, and an artifact upload in CI cannot
            # reference a path it cannot predict. A directory, an extensionless path, or
            # -Format All (which already requires a directory) still get the subfolder below.
            #
            # Split-Path has no parameter set pairing -LiteralPath with -Parent, so that
            # combination throws 'Parameter set cannot be resolved' before anything is
            # written. [System.IO.Path] is literal by nature, which keeps the -LiteralPath
            # intent (a folder named 'Contoso [2026]' must not be glob-expanded) that
            # reverting to Split-Path -Path would throw away.
            $parentFolder = [System.IO.Path]::GetDirectoryName($OutputPath)
            if ([string]::IsNullOrWhiteSpace($parentFolder)) {
              $parentFolder = (Get-Location).Path
            }
            if (-not (Test-Path -LiteralPath $parentFolder)) {
              New-Item -ItemType Directory -Path $parentFolder -Force | Out-Null
            }

            if ($wantsJson) { $resolvedJsonPath = $OutputPath }
            if ($wantsHtml) { $resolvedHtmlPath = $OutputPath }
          }
          else {
            # $namesExplicitFile is false here, which means its negation
            # ($outputIsDirectory -or -not $hasExtension -or $Format -eq 'All') is guaranteed
            # true - $OutputPath is either an existing directory, an extensionless path, or
            # -Format All (which already requires a directory), so it is always the container
            # runs get grouped under, never a filename needing its parent resolved separately.
            $baseFolder = $OutputPath
            if (-not (Test-Path -LiteralPath $baseFolder)) {
              New-Item -ItemType Directory -Path $baseFolder -Force | Out-Null
            }
            $assessmentOutputFolder = Join-Path $baseFolder $assessmentFolderName

            New-Item -ItemType Directory -Path $assessmentOutputFolder -Force | Out-Null

            if ($wantsJson) {
              $jsonLeaf = if ($Format -eq 'JSON' -and $hasExtension -and -not $outputIsDirectory) {
                [System.IO.Path]::GetFileName($OutputPath)
              }
              else {
                'MET-report.json'
              }
              $resolvedJsonPath = Join-Path $assessmentOutputFolder $jsonLeaf
            }

            if ($wantsHtml) {
              $htmlLeaf = if ($Format -eq 'HTML' -and $hasExtension -and -not $outputIsDirectory) {
                [System.IO.Path]::GetFileName($OutputPath)
              }
              else {
                'MET-report.html'
              }
              $resolvedHtmlPath = Join-Path $assessmentOutputFolder $htmlLeaf
            }
          }
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
        # (e.g. piping hand-built result objects, as the unit tests do), and also
        # $null when the results carry provenance for a different tenant than the
        # live session - $script:METSessionInfo describes whoever is connected
        # *now*, not who gathered these results, and a wrong auth description is
        # worse than none.
        $authInfoLine = $null
        # $provenanceDisagreesWithLiveSession only means the *live* session's auth details
        # would mislabel results gathered elsewhere - it says nothing about $importedAuth,
        # which describes the very run being rendered and travels beside the same tenant
        # label those results are already stamped with. So imported auth is let through
        # unconditionally when present, and the flag gates only the live-session fallback.
        $authSource = if ($importedAuth) {
            $importedAuth
        } elseif (-not $provenanceDisagreesWithLiveSession) {
            $script:METSessionInfo
        } else {
            $null
        }
        if ($authSource) {
            # $importedAuth round-tripped through JSON (Import-METReport reads it straight off
            # the saved file), so its property names are camelCase - authMode, deviceCodeUsed,
            # tenantIdentity, servicesConnected. $script:METSessionInfo is a live module-scoped
            # object with PascalCase properties. Reading either through the other's casing would
            # silently no-op under PowerShell's case-insensitive property access - the exact
            # accident C-20 exists to fix - so each source is read out explicitly rather than
            # normalized into one shared $info variable.
            if ($importedAuth) {
                $authMode          = $importedAuth.authMode
                $deviceCodeUsed    = $importedAuth.deviceCodeUsed
                $tenantIdentity    = $importedAuth.tenantIdentity
                $servicesConnected = $importedAuth.servicesConnected
            }
            else {
                $authMode          = $script:METSessionInfo.AuthMode
                $deviceCodeUsed    = $script:METSessionInfo.DeviceCodeUsed
                $tenantIdentity    = $script:METSessionInfo.TenantIdentity
                $servicesConnected = $script:METSessionInfo.ServicesConnected
            }
            $modeLabel = switch ($authMode) {
                'ServicePrincipal' { 'Service Principal (certificate)' }
                'ManagedIdentity'  { 'Managed Identity' }
                default            { if ($deviceCodeUsed) { 'Interactive (device code)' } else { 'Interactive' } }
            }
            $authInfoLine = $modeLabel
            if ($tenantIdentity) { $authInfoLine += " - $tenantIdentity" }
            if ($servicesConnected -and @($servicesConnected).Count) { $authInfoLine += " - $(@($servicesConnected) -join ', ')" }
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

            if ($band -eq 'None') {
                Write-Host '  No scorable results. Nothing was assessed - every result was Info or NotApplicable, or the set was empty.' -ForegroundColor Yellow
            }
            else {
                $scoreColor = switch ($band) {
                    'Excellent' { 'Green' }
                    'Good'      { 'Green' }
                    'Fair'      { 'Yellow' }
                    'Poor'      { 'DarkYellow' }
                    default     { 'Red' }
                }
                Write-Host "  Posture Score: $overallScore / 100  [$band]" -ForegroundColor $scoreColor
            }

            $catLine = (@('MDO','EXO','Teams') |
                Where-Object { $null -ne $categoryScores[$_] } |
                ForEach-Object { "$($_): $($categoryScores[$_])" }) -join '   '
            if ($catLine) { Write-Host "  $catLine" -ForegroundColor Gray }

            Write-Host "  Pass: $($summary.Pass)  Fail: $($summary.Fail)  Warning: $($summary.Warning)  N/A: $($summary.NotApplicable)  Info: $($summary.Info)  Error: $($summary.Error)"
            Write-Host ''

            # Sort-Object Severity is a string sort, which ordered the table
            # Critical, High, Low, Medium. Weight descending is the real order.
            # The summary puts any result carrying an Error into its own Error bucket regardless
            # of Result, so a check that failed to run with, say, NotApplicable was counted above
            # but missing from this table - which then printed 'No Fail or Warning findings'
            # underneath a non-zero Error count. Select on the same condition the summary uses.
            $actionable = $allResults |
                Where-Object { $_.Result -in 'Fail','Warning' -or $_.Error } |
                Sort-Object -Property @{ Expression = { Get-METCheckWeight -Severity (Get-METSafeSeverity -Severity $_.Severity) }; Descending = $true },
                                      @{ Expression = 'CheckId'; Descending = $false }
            if ($actionable) {
                $actionableRows = $actionable | Select-Object CheckId, Severity, AffectedObject,
                    @{ Name = 'Result'; Expression = { if ($_.Error) { 'Error' } else { $_.Result } } },
                    Finding

                Write-Host '  Issues requiring attention:' -ForegroundColor Yellow
                $actionableRows | Format-Table -AutoSize -Property @(
                    @{l='CheckId';       e={ $_.CheckId }}
                    @{l='Severity';      e={ $_.Severity }}
                    @{l='Result';        e={ $_.Result }}
                    @{l='AffectedObject';e={ $_.AffectedObject }}
                    @{l='Finding';       e={
                        $f = $_.Finding
                        if ($f.Length -gt 80) { $f.Substring(0,77) + '...' } else { $f }
                    }}
                ) | Out-String | Write-Host

                $erroredCount = @($allResults | Where-Object { $_.Error }).Count
                if ($erroredCount -gt 0) {
                    Write-Host "  ($erroredCount check(s) could not run - listed as Error in the Result column above; the exception text is in each result's Error field.)" -ForegroundColor DarkYellow
                }
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
                # Imported provenance (camelCase, from a prior Import-METReport) wins over the
                # live session (PascalCase) unconditionally when present - see the console/HTML
                # auth block above ($authSource) for why $provenanceDisagreesWithLiveSession
                # gates only the live-session fallback, and why the two shapes are read out by
                # name instead of merged through case-insensitive access.
                authentication = if ($importedAuth) {
                    [ordered]@{
                        authMode          = $importedAuth.authMode
                        deviceCodeUsed    = $importedAuth.deviceCodeUsed
                        tenantIdentity    = $importedAuth.tenantIdentity
                        servicesConnected = @($importedAuth.servicesConnected)
                    }
                } elseif ($script:METSessionInfo -and -not $provenanceDisagreesWithLiveSession) {
                    [ordered]@{
                        authMode          = $script:METSessionInfo.AuthMode
                        deviceCodeUsed    = $script:METSessionInfo.DeviceCodeUsed
                        tenantIdentity    = $script:METSessionInfo.TenantIdentity
                        servicesConnected = @($script:METSessionInfo.ServicesConnected)
                    }
                } else { $null }
                postureScore   = $overallScore
                scoreBand      = $band
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

                New-METRestrictedFile -Path $dest
                $json | Set-Content -LiteralPath $dest -Encoding UTF8
                Write-Host "  Report written: $dest" -ForegroundColor Cyan
                $writtenFiles.Add((Get-Item -LiteralPath $dest))
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

            # CONTROLS_META used to be 51 descriptions hand-maintained inside the client
            # script below - a second copy of facts the check scripts already state, which
            # had drifted for two checks. Generated here from each check's own
            # $METCheckInfo header instead, via Get-METCheck. Each description is serialized
            # with ConvertTo-Json rather than hand-escaped, so a backslash, newline, or quote
            # in a drop-in check's description can't corrupt the surrounding JS object literal.
            $controlsMetaEntries = (Get-METCheck | ForEach-Object {
                $descriptionJson = ($_.Description | ConvertTo-Json -Compress) -replace '<', '\u003C'
                "  '$($_.CheckId)': $descriptionJson,"
            }) -join "`n"

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
  /* Type scale (G-13 item 5): 11/13/15/20/28/56. 56 and 28 are each used exactly once -
     the posture score digit and the report's main title, respectively - everything else
     consolidates onto 11/13/15/20 instead of the ad-hoc 10-22px values this replaced. */
  --fs-2xs: 11px;
  --fs-xs: 13px;
  --fs-sm: 15px;
  --fs-md: 20px;
  --fs-lg: 28px;
  --fs-score: 56px;
  /* Sticky-offset for .card-group-header, kept in sync with the toolbar's actual
     rendered height by a ResizeObserver (G-codex item 5) - a hardcoded px offset
     assumed a one-row toolbar and let a wrapped two-row toolbar obscure the header. */
  --toolbar-h: 48px;
  --bg: #f3f2f1;
  --surface: #ffffff;
  --surface2: #faf9f8;
  --border: #edebe9;
  --text: #201f1e;
  --text2: #605e5c;
  /* #6b6968 on #ffffff = 5.46:1 (was #a19f9d at 2.64:1 - G-11). Used only as text/borders
     directly on the page surface - see --chip-* and --result-* below for the separate
     "opaque fill behind white text" role, which does not depend on this token or on theme. */
  --text3: #6b6968;
  /* "Surface accent" role: text, links, borders and outline-chip color read directly
     against --surface/--surface2. Lightened ~15-20% and desaturated for dark mode in the
     media query below (G-13 item 4) because a dark background changes what these need to
     look legible - unlike --chip-* and --result-* below, which are opaque fills behind a
     fixed white overlay and so need no theme-dependent adjustment at all. */
  --accent-mdo: #0078d4;
  --accent-exo: #008272;
  --accent-teams: #7719aa;
  /* "Opaque fill" role: category chip backgrounds with a white label on top. Deliberately
     NOT overridden for dark mode - lightening a fill color (as the surface accents above
     do) would wreck the white-text contrast that made it work in light mode to begin with,
     since fill-plus-fixed-text contrast has nothing to do with the surrounding page theme. */
  --chip-mdo: #0078d4;
  --chip-exo: #008272;
  --chip-teams: #7719aa;
  /* Fallback fill for an unrecognised category chip (e.g. a hostile/unknown slug) - fixed
     across themes for the same reason as --chip-*, not --text3 (which lightens for dark
     mode and would ruin the white-label contrast this fill needs). */
  --chip-neutral: #6b6968;
  /* Severity is now read from an outlined, low-chroma chip (text+border on --surface2),
     not a solid fill - see .sev-pill below (G-13 item 2). That makes this a "surface
     accent" role too, lightened for dark mode alongside --accent-*. */
  --sev-critical: #d13438;
  --sev-high: #ca5010;
  --sev-medium: #986f0b;
  --sev-low: #0078d4;
  --sev-info: #6a6866;
  /* Result now drives the card's left border/background tint and every solid result
     badge (rb-pass etc.), score band, and donut segment - an opaque-fill role like
     --chip-*, so these are also left un-overridden for dark mode. */
  --result-pass: #107c10;
  --result-fail: #d13438;
  --result-warn: #ca5010;
  --result-na: #8a8886;
  --result-accepted: #0078d4;
  /* A check that failed to run is a third state, not a severity and not a Fail/Warning -
     see .card[data-error] below (G-13 item 9). Kept neutral/slate on purpose so it never
     reads as "critical" (red) or "actionable finding" (amber/red) at a glance. */
  --result-error: #4f4f5c;
  /* Subtle per-result card background tints (G-13 item 2) - decorative, theme-specific,
     overridden below for dark mode same as the neutral surface tokens they sit beside. */
  --tint-fail: #fdf3f3;
  --tint-warn: #fdf8ef;
  --tint-pass: #f2faf3;
  --shadow: 0 2px 8px rgba(0,0,0,.08);
  --radius: 4px;
  font-size: 13px;
}
@media (prefers-color-scheme: dark) {
  :root {
    /* Widened from the original #1b1a19/#252423/#2d2c2b - three steps close enough that
       header/banner/toolbar/cards fused into one slab (G-13 item 4). */
    --bg: #16151a;
    --surface: #201f24;
    --surface2: #2b2a30;
    --border: #3d3b42;
    --text: #f3f2f1;
    --text2: #c8c6c4;
    --text3: #97949f;
    --accent-mdo: #4aa3e8;
    --accent-exo: #2fae9c;
    --accent-teams: #b088e0;
    --sev-critical: #f1707a;
    --sev-high: #e0965a;
    --sev-medium: #e0ac3d;
    --sev-low: #4aa3e8;
    --sev-info: #a29e9b;
    --tint-fail: #2a1c1e;
    --tint-warn: #2a2419;
    --tint-pass: #1b2a1c;
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
/* Main title - one of the two type-scale sizes used exactly once (G-13 item 5). */
.header-title{font-size:var(--fs-lg);font-weight:600;margin-bottom:3px;letter-spacing:-.01em}
.header-meta{font-size:var(--fs-xs);color:var(--text2)}
.header-brand{display:flex;align-items:center;gap:12px}
.header-icon{width:30px;height:30px;flex-shrink:0;color:var(--accent-mdo)}
.print-btn{font-size:var(--fs-xs);font-weight:600;color:var(--text2);border:1px solid var(--border);border-radius:var(--radius);padding:6px 12px;background:var(--surface2);white-space:nowrap;flex-shrink:0}
.print-btn:hover{background:var(--border);color:var(--text)}

/* ── Score banner (G-13 item 1: reworked to use its width - score digit up to the
   type scale's 56px, band given full-height treatment instead of an 11px pill, category
   meters doubled) ─────────────────────────────────────────────────────────────────── */
.score-banner{background:var(--surface);border-bottom:1px solid var(--border);padding:20px 24px;display:flex;align-items:stretch;gap:28px;flex-wrap:wrap;border-left:4px solid var(--border);transition:border-left-color .3s}
.score-banner[data-band="excellent"],.score-banner[data-band="good"]{border-left-color:var(--result-pass)}
.score-banner[data-band="fair"]{border-left-color:var(--sev-medium)}
.score-banner[data-band="poor"]{border-left-color:var(--sev-high)}
.score-banner[data-band="critical"]{border-left-color:var(--result-fail)}
.score-main{display:flex;flex-direction:row;align-items:center;gap:18px}
.score-donut{flex-shrink:0}
.score-main-meta{display:flex;flex-direction:column;align-items:flex-start;gap:2px}
.score-label{font-size:var(--fs-2xs);font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:var(--text2)}
.score-row{display:flex;align-items:baseline;gap:8px}
.score-delta{font-size:var(--fs-sm);font-weight:700;line-height:1}
.delta-up{color:var(--result-pass)}
.delta-down{color:var(--result-fail)}
/* G-13 item 7: the delta previously appeared with no stated baseline. */
.score-delta-caption{font-size:var(--fs-2xs);color:var(--text2);margin-top:1px}
.bar-excellent,.bar-good{background:var(--result-pass)}
.bar-fair{background:var(--sev-medium)}
.bar-poor{background:var(--sev-high)}
.bar-critical{background:var(--result-fail)}
/* Band panel: previously an 11px pill folded under the score label; now a self-contained,
   full-height block so it reads as a peer of the score, not a caption on it. */
.score-band-panel{align-self:stretch;display:flex;align-items:center;min-width:150px;padding:0 24px;border-left:1px solid var(--border);border-right:1px solid var(--border)}
.score-band-wrap{position:relative;display:flex;flex-direction:column;align-items:flex-start;gap:5px}
.score-band{font-size:var(--fs-md);font-weight:700;line-height:1;letter-spacing:-.01em}
.band-excellent,.band-good{color:var(--result-pass)}
.band-fair{color:var(--sev-medium)}
.band-poor{color:var(--sev-high)}
.band-critical{color:var(--result-fail)}
.band-none{color:var(--text2)}
.band-caption{display:flex;align-items:center;gap:6px;font-size:var(--fs-2xs);color:var(--text2);text-transform:uppercase;letter-spacing:.08em}
.band-info-icon{font-size:var(--fs-sm);color:var(--text3);cursor:default;user-select:none;line-height:1;transition:color .15s}
.score-band-wrap:hover .band-info-icon,.score-band-wrap:focus-within .band-info-icon{color:var(--text2)}
.band-tooltip{position:absolute;left:0;top:calc(100% + 10px);background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);box-shadow:0 4px 16px rgba(0,0,0,.15);padding:8px 12px;min-width:190px;display:none;z-index:200;pointer-events:none}
.score-band-wrap:hover .band-tooltip,.score-band-wrap:focus-within .band-tooltip{display:block}
.btr{display:flex;align-items:center;gap:8px;padding:3px 0;color:var(--text2);font-size:var(--fs-xs)}
.btr.cur{color:var(--text);font-weight:600}
.bdot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.brange{font-family:monospace;font-size:var(--fs-2xs);min-width:54px;color:var(--text3)}
.btr.cur .brange{color:var(--text2)}
.cat-badge{padding:4px 12px;border-radius:10px;font-size:var(--fs-xs);font-weight:600;color:#fff}
/* Opaque fills behind a fixed white label - --chip-*, not --accent-* (see :root above). */
.cat-mdo{background:var(--chip-mdo)}
.cat-exo{background:var(--chip-exo)}
.cat-teams{background:var(--chip-teams)}
/* Fallback for a category outside MDO/EXO/Teams (G-14 item 3) - same neutral fill as an
   unrecognised .card-cat-chip, so the All Controls section header for it doesn't go unstyled. */
.cat-other{background:var(--chip-neutral)}
/* Category meters at 2x: 6px tracks -> 12px, 12px labels -> the scale's 13px, filling the
   width the enlarged score/band freed up instead of leaving it empty. */
.cat-meters{display:flex;flex-direction:column;gap:10px;min-width:240px;max-width:340px;justify-content:center}
.cat-meter-row{display:grid;grid-template-columns:60px 1fr 32px;align-items:center;gap:10px;font-size:var(--fs-xs)}
.cat-meter-name{font-weight:600;color:var(--text2);display:flex;align-items:center;gap:6px}
.cat-meter-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.cat-meter-track{height:12px;background:var(--border);border-radius:6px;overflow:hidden}
.cat-meter-bar{height:100%;border-radius:6px;transition:width .4s ease,background .3s}
.card-cat-chip{font-size:var(--fs-2xs);font-weight:700;padding:2px 7px;border-radius:8px;color:#fff;white-space:nowrap;flex-shrink:0;background:var(--chip-neutral)}
.cat-meter-val{text-align:right;font-weight:700;color:var(--text2)}
.score-summary{display:flex;gap:16px;flex-wrap:wrap;font-size:var(--fs-xs);padding-left:16px;border-left:1px solid var(--border);align-items:center}
.summary-item{display:flex;flex-direction:column;align-items:center;gap:2px}
.summary-count{font-size:var(--fs-md);font-weight:700}
.summary-label{font-size:var(--fs-2xs);color:var(--text2);text-transform:uppercase;letter-spacing:.04em}
.s-pass{color:var(--result-pass)}
.s-fail{color:var(--result-fail)}
.s-warn{color:var(--result-warn)}
.s-na{color:var(--result-na)}
.s-info{color:var(--result-na)}
/* Errors get the same neutral treatment as everywhere else (G-13 item 9) - not
   --sev-critical, so a run with checks that failed to execute doesn't read as a wall of
   critical findings in the summary strip either. */
.s-err{color:var(--text2)}

/* ── Toolbar ─────────────────────────────────────────────────────── */
.toolbar{position:sticky;top:0;z-index:30;background:var(--surface);border-bottom:1px solid var(--border);padding:0 24px;display:flex;align-items:center;gap:0;flex-wrap:wrap}
.tabs{display:flex;gap:0}
.tab{padding:12px 16px;font-size:var(--fs-sm);font-weight:500;color:var(--text2);border-bottom:2px solid transparent;cursor:pointer;transition:color .15s,border-color .15s;white-space:nowrap}
.tab:hover{color:var(--text)}
.tab.active{color:var(--accent-mdo);border-bottom-color:var(--accent-mdo)}
.tab .tab-count{margin-left:6px;background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:0 6px;font-size:var(--fs-2xs);color:var(--text2)}
.filters{display:flex;align-items:center;gap:8px;margin-left:auto;padding:8px 0}
.search-box{padding:6px 10px;border:1px solid var(--border);border-radius:var(--radius);background:var(--surface2);color:var(--text);font-size:var(--fs-xs);width:220px}
.search-box::placeholder{color:var(--text3)}
.filter-select{padding:6px 8px;border:1px solid var(--border);border-radius:var(--radius);background:var(--surface2);color:var(--text);font-size:var(--fs-xs)}
.result-count{font-size:var(--fs-xs);color:var(--text2);white-space:nowrap}

/* ── Main content ────────────────────────────────────────────────── */
.main{padding:16px 24px;display:flex;flex-direction:column;gap:16px}

/* ── Top 5 ───────────────────────────────────────────────────────── */
.top5{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow);overflow:hidden}
.top5-header{padding:12px 16px;font-weight:600;font-size:var(--fs-sm);display:flex;align-items:center;justify-content:space-between;cursor:pointer;user-select:none;background:var(--surface2)}
.top5-header:hover{background:var(--border)}
.top5-chevron{font-size:var(--fs-xs);transition:transform .2s}
.top5-chevron.open{transform:rotate(180deg)}
.top5-body{border-top:1px solid var(--border);display:none}
.top5-body.open{display:block}
/* G-13 item 8: simplified to rank + id/name + the (already G-6 clamped) finding + one
   severity chip - the result badge is redundant here since every row is already a Fail or
   a Warning by construction (see renderTop5()'s filter). */
.top5-row{display:grid;grid-template-columns:32px 160px 1fr auto;gap:12px;align-items:center;padding:10px 16px;border-bottom:1px solid var(--border);cursor:pointer;transition:background .1s}
.top5-row:last-child{border-bottom:none}
.top5-row:hover{background:var(--surface2)}
.top5-rank{font-size:var(--fs-md);font-weight:700;color:var(--text2);text-align:center}
.top5-id{font-size:var(--fs-2xs);font-family:monospace;color:var(--text2)}
.top5-name{font-weight:500;font-size:var(--fs-xs)}
.top5-finding{font-size:var(--fs-xs);color:var(--text2);line-height:1.5;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.finding-policy{margin-bottom:6px}.finding-policy:last-child{margin-bottom:0}
.finding-policy-name{font-weight:600;color:var(--text)}
.finding-list{margin:3px 0 0 0;padding-left:16px;list-style:disc}
.finding-list li{margin:2px 0}
.finding-list-indent{padding-left:20px}
.code-block{font-family:'Cascadia Code','Consolas',monospace;font-size:var(--fs-xs);background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:5px 10px;margin-top:6px;word-break:break-all;display:block;color:var(--text)}
.finding-code{margin-left:12px}
.inline-code{font-family:'Cascadia Code','Consolas',monospace;font-size:var(--fs-xs);background:var(--surface2);border:1px solid var(--border);border-radius:3px;padding:1px 5px;color:var(--text);word-break:break-word}
/* codifyQuotes applies this instead of the 5px default right padding when the chip is
   immediately followed by punctuation with no space (e.g. "...p=quarantine.") - the full
   padding plus the chip's border otherwise reads as a stray space before the punctuation
   (G-14 item 2). */
.inline-code--tight{padding-right:1px}
.coverage-wrap{margin-top:8px;overflow-x:auto}
.coverage-summary{font-size:var(--fs-xs);color:var(--text2);margin-bottom:8px}
.coverage-table{width:100%;border-collapse:collapse;font-size:var(--fs-xs)}
.coverage-table th{text-align:left;padding:6px 8px;background:var(--surface2);color:var(--text2);border:1px solid var(--border);white-space:nowrap}
.coverage-table td{padding:7px 8px;border:1px solid var(--border);vertical-align:top}
.coverage-table .coverage-policy{font-weight:600;white-space:nowrap}
.coverage-table .coverage-zero{color:var(--text2)}

/* ── Cards grid (G-13 item 3): grouped by result with sticky, collapsible headers that
   surface counts at a glance, instead of 30+ identical shadowed boxes with no structure.
   Mirrors the density of the All Controls table (#ctrl-ref) - one bordered container per
   group instead of one per card. See renderCardGroups()/rebuildCard() in the script. ── */
.cards{display:flex;flex-direction:column;gap:20px}
.no-results{text-align:center;padding:48px;color:var(--text2)}

/* overflow:hidden lives on .card-group-body, not .card-group itself - an overflow:hidden
   ancestor breaks position:sticky on the header (it becomes the header's own scroll
   container, so it "sticks" immediately instead of tracking the real page scroll). */
.card-group{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow)}
.card-group-header{position:sticky;top:var(--toolbar-h);z-index:20;display:flex;align-items:center;justify-content:space-between;gap:8px;padding:8px 14px;background:var(--surface2);border-bottom:1px solid var(--border);cursor:pointer;user-select:none;font-size:var(--fs-2xs);font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--text2);border-top-left-radius:var(--radius);border-top-right-radius:var(--radius)}
.card-group-header:hover{color:var(--text)}
.card-group-title{display:flex;align-items:center;gap:8px}
.card-group-count{font-weight:700;color:var(--text3)}
.card-group-chevron{font-size:var(--fs-xs);color:var(--text3);transition:transform .2s;flex-shrink:0}
.card-group-chevron.open{transform:rotate(180deg)}
.card-group-body{display:flex;flex-direction:column;overflow:hidden;border-bottom-left-radius:var(--radius);border-bottom-right-radius:var(--radius)}
.card-group-body.collapsed{display:none}
.card-group.empty{display:none}

/* ── Card row: a ~36px hairline-divided row by default, not an individually boxed/shadowed
   card - the group container above now carries the border/shadow every card used to carry
   on its own. Expanding a row (.card-body.open) is the only thing that grows its height. */
.card{border-bottom:1px solid var(--border);border-left:4px solid transparent;transition:background .15s}
.card:last-child{border-bottom:none}
/* Result drives the left border and a subtle background tint; severity moves to a
   low-chroma outlined chip instead (G-13 item 2 - see .sev-pill below). Pass gets only a
   thin, quiet accent: a passing control is not the thing asking for the reader's attention. */
.card[data-result="Fail"]{border-left-color:var(--result-fail);background:var(--tint-fail)}
.card[data-result="Warning"]{border-left-color:var(--result-warn);background:var(--tint-warn)}
.card[data-result="Pass"]{border-left-color:var(--result-pass);background:var(--tint-pass)}
.card[data-result="NotApplicable"],.card[data-result="Info"]{border-left-color:var(--border)}
/* Accepted overrides the Fail/Warning tint above - a resolved risk should read as settled,
   not still-urgent (source order after the per-result rules is what makes this win). */
.card[data-accepted="1"]{border-left-color:var(--result-accepted);background:var(--surface)}
/* A check that failed to run is a third state - not a severity, and not simply "Fail" or
   "Warning" repainted red/amber (G-13 item 9). Dashed and neutral so tool-failure can never
   be mistaken for a critical finding or a resolved risk; wins over both rules above. */
/* border-style:dashed alone produces too few, too-long dashes to read at a ~36px collapsed
   row height - a diagonal hazard-stripe fill on the left edge reads as "third state" at
   any row height, including collapsed. */
.card[data-error="1"]{border-left-color:transparent;background:var(--surface);position:relative}
.card[data-error="1"]::before{content:'';position:absolute;left:0;top:0;bottom:0;width:4px;background-image:repeating-linear-gradient(135deg,var(--result-error) 0 3px,transparent 3px 6px)}
.card-header{display:flex;align-items:center;gap:10px;padding:8px 14px;cursor:pointer;user-select:none;min-height:36px}
.card-header:hover{background:var(--surface2)}
/* One rule for every interactive element on the page (G-14 item 9) - native <button>/<a>/
   <input>/<select> got the UA default ring, .card-header had its own explicit ring, and
   .fix-toggle (a div[role=button][tabindex=0]) had none at all. */
.card-header:focus-visible,.fix-toggle:focus-visible,.tab:focus-visible,.band-info-icon:focus-visible,.top5-row:focus-visible,.ctrl-row:focus-visible,button:focus-visible,a:focus-visible,input:focus-visible,select:focus-visible{outline:2px solid var(--accent-mdo);outline-offset:-2px}
/* Low-chroma outlined chip: severity describes the control, not this run's finding, so it
   no longer competes with the result badge for the reader's attention (G-13 item 2). */
.sev-pill{font-size:var(--fs-2xs);font-weight:700;padding:1px 7px;border-radius:8px;white-space:nowrap;flex-shrink:0;background:var(--surface2);border:1px solid var(--border);color:var(--text2)}
.sev-critical{border-color:var(--sev-critical);color:var(--sev-critical)}
.sev-high{border-color:var(--sev-high);color:var(--sev-high)}
.sev-medium{border-color:var(--sev-medium);color:var(--sev-medium)}
.sev-low{border-color:var(--sev-low);color:var(--sev-low)}
.sev-informational{border-color:var(--sev-info);color:var(--sev-info)}
/* Fully desaturated on Pass, whatever the underlying severity - severity is inert once the
   control has passed, and a solid CRITICAL-red pill on a PASS row is exactly the
   loudest-channel/quietest-channel inversion this item exists to fix. */
.sev-pill.is-pass{border-color:var(--border) !important;color:var(--text3) !important;background:var(--surface2) !important}
.card-id{font-size:var(--fs-2xs);font-family:monospace;color:var(--text2);flex-shrink:0}
.card-name{font-weight:600;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.result-badge{font-size:var(--fs-2xs);font-weight:700;padding:2px 8px;border-radius:8px;flex-shrink:0;color:#fff;background:var(--result-na)}
.rb-pass{background:var(--result-pass)}
.rb-fail{background:var(--result-fail)}
.rb-warning{background:var(--result-warn)}
.rb-notapplicable,.rb-info{background:var(--result-na)}
.rb-accepted{background:var(--result-accepted)}
.rb-error{background:var(--result-error)}
.card-chevron{font-size:var(--fs-2xs);color:var(--text3);flex-shrink:0;transition:transform .2s}
.card-chevron.open{transform:rotate(180deg)}
.card-body{display:none;border-top:1px solid var(--border);padding:12px 14px;flex-direction:column;gap:10px}
.card-body.open{display:flex}
.card-field{display:flex;flex-direction:column;gap:2px}
.field-label{font-size:var(--fs-2xs);font-weight:600;text-transform:uppercase;color:var(--text2);letter-spacing:.04em}
.field-value{font-size:var(--fs-xs);color:var(--text);white-space:pre-wrap;word-break:break-word;max-width:78ch}
/* The Effective Policy Coverage table needs its full width (it has its own horizontal
   scroll via .coverage-wrap) - the 78ch cap above is for prose (Finding/Recommendation),
   not tabular data, so this field is opted back out of it. */
.field-value--wide{max-width:none}
.card-fix{border-top:1px solid var(--border);padding-top:10px}
.fix-toggle{display:flex;align-items:center;gap:6px;font-size:var(--fs-xs);font-weight:500;cursor:pointer;color:var(--accent-mdo);padding:2px 0}
.fix-toggle:hover{text-decoration:underline}
.fix-chevron{font-size:var(--fs-2xs);transition:transform .2s}
/* &#x25BA; (right-pointing triangle) rotated a further 90deg points down when the
   section is open - the same "collapsed points at the content, open points down"
   convention as .card-chevron. 180deg previously rotated it to point left (G-14 item 1). */
.fix-chevron.open{transform:rotate(90deg)}
.fix-content{display:none;margin-top:8px;font-size:var(--fs-xs);color:var(--text);line-height:1.5;max-width:78ch}
.fix-content.open{display:block}
.fix-content ol{padding-left:18px;display:flex;flex-direction:column;gap:4px}
.card-actions{display:flex;align-items:center;gap:12px;flex-wrap:wrap;padding-top:4px}
.btn-docs{font-size:var(--fs-xs);color:var(--accent-mdo);padding:4px 0;display:flex;align-items:center;gap:4px}
.btn-docs:hover{text-decoration:underline}
.btn-accept{font-size:var(--fs-xs);color:var(--text2);border:1px solid var(--border);border-radius:var(--radius);padding:4px 10px;background:var(--surface2);transition:background .1s}
.btn-accept:hover{background:var(--border)}
.btn-undo{font-size:var(--fs-xs);color:var(--result-accepted);border:1px solid var(--result-accepted);border-radius:var(--radius);padding:4px 10px;background:var(--surface);transition:background .1s}
.btn-undo:hover{background:var(--surface2)}
/* Low-chroma, near-white-on-dark treatment (G-13 item 4 / G-11): was a saturated red box
   in both themes (#d13438 on #fde7e9 = 4.16:1 light, #d13438 on #3a1010 = ~3.35:1 dark -
   the second failed AA outright). Built entirely from the existing neutral --text/--surface2
   pair, which is already high-contrast in both themes by construction, so this needs no
   theme-specific override at all - and it reads as "tool failure", not "critical finding",
   consistent with the dashed neutral card border above. */
.card-error{background:var(--surface2);border:1px dashed var(--border);border-radius:var(--radius);padding:8px 10px;font-size:var(--fs-xs);font-family:monospace;color:var(--text);word-break:break-word}

/* ── Accept modal ────────────────────────────────────────────────── */
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:1000;align-items:center;justify-content:center}
.modal-overlay.open{display:flex}
.modal{background:var(--surface);border-radius:var(--radius);box-shadow:0 8px 32px rgba(0,0,0,.24);padding:24px;width:480px;max-width:90vw;display:flex;flex-direction:column;gap:16px}
.modal-title{font-size:var(--fs-md);font-weight:600}
.modal-desc{font-size:var(--fs-xs);color:var(--text2)}
.modal textarea{border:1px solid var(--border);border-radius:var(--radius);padding:8px;font-family:inherit;font-size:var(--fs-xs);background:var(--surface2);color:var(--text);resize:vertical;min-height:80px;width:100%}
.modal textarea:focus{outline:2px solid var(--accent-mdo);border-color:transparent}
.modal-actions{display:flex;gap:8px;justify-content:flex-end}
.btn-primary{background:var(--chip-mdo);color:#fff;padding:6px 16px;border-radius:var(--radius);font-size:var(--fs-xs);font-weight:600;transition:opacity .1s}
.btn-primary:hover{opacity:.9}
.btn-primary:disabled{opacity:.4;cursor:not-allowed}
.btn-secondary{background:var(--surface2);color:var(--text);border:1px solid var(--border);padding:6px 16px;border-radius:var(--radius);font-size:var(--fs-xs)}
.btn-secondary:hover{background:var(--border)}

/* ── Collapse / Expand all ───────────────────────────────────────── */
.btn-collapse{font-size:var(--fs-xs);color:var(--text2);border:1px solid var(--border);border-radius:var(--radius);padding:5px 10px;background:var(--surface2);transition:background .1s;white-space:nowrap}
.btn-collapse:hover{background:var(--border)}

/* ── Controls Reference ──────────────────────────────────────────── */
.ctrl-ref{display:none;flex-direction:column;gap:16px}
.ctrl-ref.visible{display:flex}
.ctrl-section{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;box-shadow:var(--shadow)}
.ctrl-section-header{padding:12px 16px;font-weight:600;display:flex;align-items:center;gap:10px;background:var(--surface2);border-bottom:1px solid var(--border);font-size:var(--fs-sm)}
.ctrl-table{width:100%;border-collapse:collapse;font-size:var(--fs-xs)}
.ctrl-table th{padding:8px 12px;text-align:left;font-size:var(--fs-2xs);font-weight:600;text-transform:uppercase;letter-spacing:.04em;color:var(--text2);border-bottom:1px solid var(--border);background:var(--surface2)}
.ctrl-table td{padding:10px 12px;border-bottom:1px solid var(--border);vertical-align:middle}
.ctrl-table tr:last-child td{border-bottom:none}
.ctrl-row{cursor:pointer;transition:background .1s}
.ctrl-row:hover{background:var(--surface2)}
.ctrl-id{font-family:monospace;font-size:var(--fs-2xs);white-space:nowrap;color:var(--text2)}
.ctrl-name{font-weight:500;white-space:nowrap}
.ctrl-desc{color:var(--text2)}

/* ── Print ───────────────────────────────────────────────────────── */
@media print {
  body{background:#fff}
  .toolbar,.print-btn,.modal-overlay,.band-info-icon,.card-chevron,.fix-chevron,.btn-accept,.btn-undo,.btn-collapse,.card-group-chevron{display:none !important}
  .card{display:block !important;box-shadow:none;break-inside:avoid}
  .card-group-header{position:static}
  .card-group.empty{display:block !important}
  .card-group-body.collapsed{display:flex !important}
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
    <svg class="score-donut" width="132" height="132" viewBox="0 0 132 132" aria-hidden="true">
      <circle cx="66" cy="66" r="54" fill="none" stroke="var(--surface2)" stroke-width="14"></circle>
      <g id="donut-segments" transform="rotate(-90 66 66)"></g>
      <text x="66" y="84" text-anchor="middle" style="font-size:var(--fs-score)" font-weight="700" fill="var(--text)" id="donut-score-text">$overallScore</text>
    </svg>
    <div class="score-main-meta">
      <div class="score-label">Posture Index</div>
      <div class="score-row">
        <div class="score-delta" id="score-delta"></div>
      </div>
      <div class="score-delta-caption" id="score-delta-caption" style="display:none">vs. last viewed run</div>
    </div>
  </div>
  <div class="score-band-panel">
    <div class="score-band-wrap">
      <div class="score-band band-$(($band).ToLower())" id="score-band">$band</div>
      <div class="band-caption">
        <span>Posture Band</span>
        <span class="band-info-icon" tabindex="0" aria-label="Band scale guide">&#x24D8;</span>
      </div>
      <div class="band-tooltip" id="band-tooltip" role="tooltip"></div>
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
  <div class="tabs" role="tablist">
    <div class="tab active" data-tab="All" role="tab" tabindex="0" aria-selected="true" aria-controls="cards-container">All <span class="tab-count" id="tc-all">0</span></div>
    <div class="tab" data-tab="Top5" role="tab" tabindex="-1" aria-selected="false" aria-controls="top5-section">Top 5 Remediation</div>
    <div class="tab" data-tab="MDO" role="tab" tabindex="-1" aria-selected="false" aria-controls="cards-container">MDO <span class="tab-count" id="tc-mdo">0</span></div>
    <div class="tab" data-tab="EXO" role="tab" tabindex="-1" aria-selected="false" aria-controls="cards-container">EXO <span class="tab-count" id="tc-exo">0</span></div>
    <div class="tab" data-tab="Teams" role="tab" tabindex="-1" aria-selected="false" aria-controls="cards-container">Teams <span class="tab-count" id="tc-teams">0</span></div>
    <div class="tab" data-tab="Accepted" role="tab" tabindex="-1" aria-selected="false" aria-controls="cards-container">Accepted <span class="tab-count" id="tc-accepted">0</span></div>
    <div class="tab" data-tab="Controls" role="tab" tabindex="-1" aria-selected="false" aria-controls="ctrl-ref">All Controls <span class="tab-count" id="tc-controls">0</span></div>
  </div>
  <div class="filters">
    <input type="text" class="search-box" id="search" placeholder="&#x1F50D; Search..." aria-label="Search checks">
    <select class="filter-select" id="sev-filter" aria-label="Filter by severity">
      <option value="">All Severities</option>
      <option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Informational</option>
    </select>
    <select class="filter-select" id="result-filter" aria-label="Filter by result">
      <option value="">All Results</option>
      <option>Fail</option><option>Warning</option><option>Pass</option><option>NotApplicable</option><option>Info</option><option>Error</option>
    </select>
    <span class="result-count" id="result-count" aria-live="polite"></span>
    <button class="btn-collapse" id="btn-collapse-all" title="Collapse or expand all visible cards">Collapse All</button>
  </div>
</div>

<div class="main">
  <div class="top5" id="top5-section" role="tabpanel" aria-label="Top 5 Remediation Actions">
    <div class="top5-header" id="top5-toggle">
      <span>&#x1F4CB; Top 5 Remediation Actions</span>
      <span class="top5-chevron open" id="top5-chevron">&#x25BC;</span>
    </div>
    <div class="top5-body open" id="top5-body"></div>
  </div>
  <div class="cards" id="cards-container" role="tabpanel" aria-label="Checks"></div>
  <div class="no-results" id="no-results" style="display:none">$(if ($allResults.Count -eq 0) { 'No check results in this report.' } else { 'No checks match the current filters.' })</div>
  <div class="ctrl-ref" id="ctrl-ref" role="tabpanel" aria-label="All Controls"></div>
</div>

<div class="modal-overlay" id="modal-overlay">
  <div class="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title" aria-describedby="modal-desc">
    <div class="modal-title" id="modal-title">Accept Risk</div>
    <div class="modal-desc" id="modal-desc">Provide a business justification for accepting this risk.</div>
    <textarea id="modal-text" maxlength="4000" placeholder="Business justification (required)..."></textarea>
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
const IS_EMPTY_REPORT = CHECKS.length === 0;
const TENANT_ID = $tenantIdJson;
const INITIAL_SCORE = $overallScore;
const SEV_WEIGHT = {Critical:40,High:20,Medium:10,Low:5,Informational:0};
const CAT_ACCENT = {MDO:'var(--accent-mdo)',EXO:'var(--accent-exo)',Teams:'var(--accent-teams)'};
// A risk-acceptance justification is a business note, not a document - 4000 characters
// (roughly a page of text) is generous for that while keeping a single localStorage entry
// well clear of QuotaExceededError. Mirrors the textarea's maxlength attribute above.
const JUSTIFICATION_MAX_LENGTH = 4000;

function sevOf(s){ return s || 'Informational'; }

// Mirrors Get-METAggregationNoun in Public/Invoke-METAssessment.ps1 so a grouped Top 5 row
// (see renderTop5()) uses the same per-checkId noun as the console/JSON aggregation path.
function getAggregationNoun(checkId) {
  if (/^MET-EXO00[1-3]$/.test(checkId)) return 'domains';
  if (checkId === 'MET-EXO004') return 'quarantine policies';
  if (checkId === 'MET-EXO018') return 'remote domains';
  if (checkId === 'MET-EXO020') return 'connection filter policies';
  if (checkId === 'MET-EXO022') return 'sharing policies';
  if (checkId === 'MET-MDO014') return 'groups';
  return 'policies';
}

const CONTROLS_META = {
$controlsMetaEntries
};

// Renders every category actually present in CHECKS, not just the three MET ships today
// (see CLAUDE.md) - a hardcoded 3-entry list would let a typo'd or future category vanish
// from the All Controls table while #tc-controls (derived from CHECKS.length) kept counting
// it, so the tab badge and the visible table disagreed (G-14 item 3).
const CONTROLS_CATEGORY_META = {
  MDO:   { label: 'Microsoft Defender for Office 365',      cls: 'cat-mdo'   },
  EXO:   { label: 'Exchange Online / Email Authentication',  cls: 'cat-exo'   },
  Teams: { label: 'Microsoft Teams Protection',              cls: 'cat-teams' }
};
const CONTROLS_CATEGORIES = (function() {
  const knownOrder = ['MDO', 'EXO', 'Teams'];
  const seen = {};
  const list = knownOrder.map(function(id) {
    seen[id] = true;
    return { id: id, label: CONTROLS_CATEGORY_META[id].label, cls: CONTROLS_CATEGORY_META[id].cls };
  });
  CHECKS.forEach(function(c) {
    const id = c.category;
    if (id && !seen[id]) {
      seen[id] = true;
      list.push({ id: id, label: id, cls: 'cat-other' });
    }
  });
  return list;
})();

// ── Result identity ──────────────────────────────────────────────
// Invoke-METAssessment -Detailed routinely emits several results sharing one CheckId (one per
// domain/policy/mailbox). CheckId alone is not a unique identity for a result, so every
// acceptance helper, cardMap, and click target below is keyed on resultKey(check) instead.
// checkId + affectedObject alone is not enough either: MET-EXO006 emits ten independent
// sections that all report AffectedObject 'Report Submission Policy', so several results can
// share both fields in normal runs, not just in a hypothetical edge case. name is folded in
// as a third component - it is already present on every check payload, is distinct across
// EXO006's sections, and is exactly as stable across page loads/regenerations as checkId and
// affectedObject are, so this preserves the stability property that ruled out a render-time
// index (order can shift between runs, and the key must survive a reload for accepted state
// to mean anything).
function resultKey(c){ return c.checkId + '|' + (c.name || '') + '|' + (c.affectedObject || ''); }

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
// Deliberately NOT migrated from the legacy 'MET_accepted_<tenant>_<checkId>' scheme - those
// entries are already collided under the CheckId-only scheme, so migrating would propagate a
// wrong acceptance state into the new per-result scheme. Existing acceptances are dropped.
function lsKey(key){ return 'MET_accepted_' + TENANT_ID + '_' + key; }
function isAccepted(key){ return !!lsGet(lsKey(key)); }
// Stored value is JSON: { justification, acceptedAt }. Older reports wrote a bare
// justification string with no date at all - parsed defensively here so that data keeps
// working: a value that isn't valid JSON, or doesn't have the expected shape, is treated as
// the raw justification string with no acceptedAt, rather than dropped or shown as
// "undefined"/"[object Object]".
function getAcceptance(key) {
  const raw = lsGet(lsKey(key));
  if (raw === null) return null;
  try {
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === 'object' && typeof parsed.justification === 'string') {
      return { justification: parsed.justification, acceptedAt: parsed.acceptedAt || null };
    }
  } catch (e) { /* legacy bare-string value - fall through */ }
  return { justification: raw, acceptedAt: null };
}
function setAccepted(key, justification){
  lsSet(lsKey(key), JSON.stringify({ justification: justification || 'Accepted', acceptedAt: new Date().toISOString() }));
}
function clearAccepted(key){ lsRemove(lsKey(key)); }

// ── Score calculation ────────────────────────────────────────────
function bandOf(score) {
  if (score === null || score === undefined) return 'None';
  return score >= 95 ? 'Excellent' : score >= 80 ? 'Good' : score >= 60 ? 'Fair' : score >= 40 ? 'Poor' : 'Critical';
}
function weightedScore(checks) {
  let wSum = 0, wTotal = 0;
  checks.forEach(function(c) {
    if (!['Pass','Fail','Warning'].includes(c.result)) return;
    if (c.score === null || c.score === undefined) return;
    if (isAccepted(resultKey(c))) return;
    const w = SEV_WEIGHT[c.severity] || 0;
    wSum  += c.score * w;
    wTotal += w * 100;
  });
  return wTotal > 0 ? Math.round((wSum / wTotal) * 100) : null;
}
function recalcScore() {
  const raw = IS_EMPTY_REPORT ? null : weightedScore(CHECKS);
  const score = raw ?? 0;
  const band = IS_EMPTY_REPORT ? 'None' : bandOf(raw);
  document.getElementById('donut-score-text').textContent = IS_EMPTY_REPORT ? '\u2014' : score;
  const bandEl = document.getElementById('score-band');
  bandEl.textContent = IS_EMPTY_REPORT ? 'No data' : band;
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
  const fail  = CHECKS.filter(function(c) { return c.result === 'Fail' && !isAccepted(resultKey(c)) && !c.error; }).length;
  const warn  = CHECKS.filter(function(c) { return c.result === 'Warning' && !isAccepted(resultKey(c)) && !c.error; }).length;
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
    { v: error, color: 'var(--result-error)'  }
  ].filter(function(s) { return s.v > 0; });
  const r = 54, circ = 2 * Math.PI * r;
  let offset = 0;
  segs.forEach(function(s) {
    const len = (s.v / total) * circ;
    const c = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    c.setAttribute('cx', 66); c.setAttribute('cy', 66); c.setAttribute('r', r);
    c.setAttribute('fill', 'none'); c.setAttribute('stroke', s.color); c.setAttribute('stroke-width', 14);
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
    // A chip immediately followed by punctuation with no space in between (e.g.
    // "p=quarantine.") gets the tighter right padding so the chip's own box doesn't read
    // as a stray space before that punctuation (G-14 item 2).
    const nextChar = s.charAt(re.lastIndex);
    const cls = nextChar && /[.,;:!?)\]}]/.test(nextChar) ? 'inline-code inline-code--tight' : 'inline-code';
    if (m[1] !== undefined) {
      out += '<code class="' + cls + '">' + esc(m[1]) + '</code>';
    } else {
      out += esc(m[2]) + '<code class="' + cls + '">' + esc(m[3]) + '</code>';
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
  const key        = resultKey(check);
  const accepted   = isAccepted(key);
  const hasError   = !!check.error;
  const isFailWarn = ['Fail','Warning'].includes(check.result);
  const showFix    = isFailWarn || hasError;
  const isPass     = check.result === 'Pass';
  // A check can carry both a Result (e.g. NotApplicable) and a populated Error field when it
  // couldn't run - the badge must say ERROR so the card is findable, even though card.dataset.result
  // (used by the result-filter dropdown and tab scoping below) stays the real Result value. hasError
  // wins over accepted: a synthetic Fail from a crashed check (see Invoke-METAssessment's per-check catch)
  // can be risk-accepted like any other Fail, and an accepted check still carrying an Error is exactly
  // the "error with no findable card" bug this fix closes - just for accepted checks instead of all of them.
  const resultDisplay = hasError ? 'Error' : (accepted ? 'Accepted' : check.result);
  const rbClass    = 'rb-' + (hasError ? 'error' : (accepted ? 'accepted' : slug(check.result)));
  const startOpen  = false;

  const card = document.createElement('div');
  card.className = 'card';
  card.dataset.checkId   = check.checkId;
  card.dataset.resultKey = key;
  card.dataset.category = check.category;
  card.dataset.result   = check.result;
  card.dataset.sev      = sevOf(check.severity);
  card.dataset.accepted = accepted ? '1' : '0';
  card.dataset.error    = hasError ? '1' : '0';
  // Which card-group this row belongs to (G-13 item 3) - the underlying Result (Error wins,
  // same as the badge), deliberately NOT re-derived from `accepted`. Accept/undo never move
  // a card to a different DOM parent (see rebuildCard()): the Accepted tab's own filtering
  // (inScope, in applyFilters()) already scopes to accepted cards regardless of which group
  // contains them, and grouping by original Fail/Warning/... there is informative in its own
  // right (which accepted risks were Fails vs. Warnings) rather than lumping everything
  // under one undifferentiated "Accepted" bucket. Keeping the group fixed for a card's whole
  // lifetime also keeps DOM order stable across an accept/undo, which the Accept Risk flow
  // and its tests depend on (a locator like `[data-check-id=X].nth(0)` must keep meaning
  // "the same card", not silently repoint to a sibling because acceptance re-sorted it).
  card.dataset.group    = hasError ? 'Error' : check.result;
  card.dataset.search   = [check.checkId, check.name, check.affectedObject, check.finding].join(' ').toLowerCase();

  const bodyOpen = startOpen ? ' open' : '';

  let actionsHtml = '';
  if (check.referenceUrl) {
    actionsHtml += '<a class="btn-docs" href="' + safeHref(check.referenceUrl) + '" target="_blank" rel="noopener">&#x1F4D6; Microsoft Docs</a>';
  }
  if (['Fail','Warning'].includes(check.result) && !accepted) {
    actionsHtml += '<button class="btn-accept" data-checkid="' + esc(check.checkId) + '" data-result-key="' + esc(key) + '">&#x2713; Accept Risk</button>';
  }
  if (accepted) {
    const acceptance = getAcceptance(key) || { justification: 'Accepted', acceptedAt: null };
    const just = esc(acceptance.justification || 'Accepted');
    let dateHtml = '';
    if (acceptance.acceptedAt) {
      const acceptedAtDate = new Date(acceptance.acceptedAt);
      if (!isNaN(acceptedAtDate.getTime())) {
        dateHtml = ' <span class="accepted-date">(' + esc(acceptedAtDate.toLocaleString()) + ')</span>';
      }
    }
    actionsHtml += '<span style="font-size:var(--fs-xs);color:var(--result-accepted)">Accepted: ' + just + dateHtml + '</span>';
    actionsHtml += '<button class="btn-undo" data-checkid="' + esc(check.checkId) + '" data-result-key="' + esc(key) + '">Undo acceptance</button>';
  }

  const errorHtml = check.error
    ? '<div class="card-error">Check failed: ' + esc(check.error) + '</div>'
    : '';
  const coverageHtml = fmtEffectivePolicyCoverage(check);

  const fixHtml = (check.recommendation || errorHtml) ? (
    '<div class="card-fix">' +
    '<div class="fix-toggle" tabindex="0" role="button">' +
    '<span class="fix-chevron">&#x25BA;</span> ' + (hasError ? 'Details' : 'How to fix') + '</div>' +
    '<div class="fix-content">' +
    errorHtml + buildRecommendation(check.recommendation) +
    '</div></div>'
  ) : '';

  // A property the check never populated must not render as a labelled field with nothing
  // under it (G-14 item 6) - skip the whole .card-field instead of emitting an empty value.
  const affectedObjectHtml = check.affectedObject
    ? '<div class="card-field"><span class="field-label">Affected Object</span><span class="field-value" dir="auto">' + esc(check.affectedObject) + '</span></div>'
    : '';
  // fmtFinding() can return block content (<div class="finding-policy">, <ul>) for
  // multi-line/multi-policy findings, so this needs a block container too, not the
  // <span> every purely-textual field-value uses - a <span> around block content is a
  // parse-tree hazard browsers silently repair (same fix as the coverage table below,
  // G-14 item 7).
  const findingValueHtml = fmtFinding(check.finding);
  const findingHtml = findingValueHtml
    ? '<div class="card-field"><span class="field-label">Finding</span><div class="field-value" dir="auto">' + findingValueHtml + '</div></div>'
    : '';
  // A <table> (coverageHtml) needs a block container, not the <span> every other field-value
  // uses - a <span> around block content is a parse-tree hazard browsers silently repair
  // (G-14 item 7).
  const coverageFieldHtml = coverageHtml
    ? '<div class="card-field"><span class="field-label">Effective Policy Coverage</span><div class="field-value field-value--wide" dir="auto">' + coverageHtml + '</div></div>'
    : '';

  card.innerHTML =
    '<div class="card-header" role="button" tabindex="0" aria-expanded="' + (startOpen ? 'true' : 'false') + '">' +
      '<span class="sev-pill sev-' + slug(sevOf(check.severity)) + (isPass ? ' is-pass' : '') + '">' + esc(sevOf(check.severity).toUpperCase()) + '</span>' +
      '<span class="card-cat-chip cat-' + slug(check.category) + '">' + esc(check.category) + '</span>' +
      '<span class="card-id">' + esc(check.checkId) + '</span>' +
      '<span class="card-name" dir="auto">' + esc(check.name || check.checkId) + '</span>' +
      '<span class="result-badge ' + rbClass + '">' + esc(resultDisplay.toUpperCase()) + '</span>' +
      '<span class="card-chevron' + (startOpen ? ' open' : '') + '">&#x25BC;</span>' +
    '</div>' +
    '<div class="card-body' + bodyOpen + '">' +
      affectedObjectHtml +
      findingHtml +
      coverageFieldHtml +
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

// ── Render all cards, grouped by result (G-13 item 3) ─────────────
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

// One group per possible card.dataset.group value (see createCard()) - the underlying
// Result, Error included, NOT Accepted (accepted cards stay grouped by their original
// Result for the reasons explained at card.dataset.group's assignment in createCard()).
// Built once up front in a fixed, sensible order; a group with zero current members is
// hidden entirely by updateGroupHeaders(), never shown as e.g. "PASS · 0" noise.
const GROUP_ORDER  = ['Fail','Warning','Error','Pass','Info','NotApplicable'];
const GROUP_LABELS = {
  Fail: 'Fail', Warning: 'Warning', Error: 'Error', Pass: 'Pass',
  Info: 'Info', NotApplicable: 'Not Applicable'
};
const groupEls = {};
function toggleGroup(g) {
  const state = groupEls[g];
  if (!state) return;
  state.collapsed = !state.collapsed;
  state.body.classList.toggle('collapsed', state.collapsed);
  state.chevron.classList.toggle('open', !state.collapsed);
  state.header.setAttribute('aria-expanded', state.collapsed ? 'false' : 'true');
}
function ensureGroupExpanded(card) {
  const g = card && card.dataset.group;
  if (g && groupEls[g] && groupEls[g].collapsed) toggleGroup(g);
}
GROUP_ORDER.forEach(function(g) {
  const wrap = document.createElement('div');
  wrap.className = 'card-group';
  wrap.dataset.group = g;

  const header = document.createElement('div');
  header.className = 'card-group-header';
  header.setAttribute('role', 'button');
  header.setAttribute('tabindex', '0');
  header.setAttribute('aria-expanded', 'true');
  header.innerHTML =
    '<span class="card-group-title">' + esc(GROUP_LABELS[g].toUpperCase()) +
    ' <span class="card-group-count">0</span></span>' +
    '<span class="card-group-chevron open">&#x25BC;</span>';
  header.addEventListener('click', function() { toggleGroup(g); });
  header.addEventListener('keydown', function(e) {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggleGroup(g); }
  });

  const body = document.createElement('div');
  body.className = 'card-group-body';

  wrap.appendChild(header);
  wrap.appendChild(body);
  container.appendChild(wrap);

  groupEls[g] = {
    wrap: wrap, header: header, body: body,
    countEl: header.querySelector('.card-group-count'),
    chevron: header.querySelector('.card-group-chevron'),
    collapsed: false
  };
});

const cardMap = {};
sortedChecks.forEach(function(check) {
  const card = createCard(check);
  const group = groupEls[card.dataset.group] || groupEls.Info;
  group.body.appendChild(card);
  cardMap[resultKey(check)] = card;
});

// Recomputes each group's visible-card count from the cards currently shown, and hides a
// group entirely when nothing in it matches the active tab/search/filters - called from
// applyFilters() below so grouping never drifts out of sync with what filtering shows.
function updateGroupHeaders(groupVisibleCounts) {
  GROUP_ORDER.forEach(function(g) {
    const state = groupEls[g];
    if (!state) return;
    const count = groupVisibleCounts[g] || 0;
    state.countEl.textContent = count;
    state.wrap.classList.toggle('empty', count === 0);
  });
}

// ── Top 5 ────────────────────────────────────────────────────────
function renderTop5() {
  // G-5: group actionable results by CheckId and rank by summed severity weight, per
  // CLAUDE.md's "Severity weight × number of Fail results sharing the same remediation
  // category." A check whose Error field is populated couldn't be assessed at all, so it
  // is excluded before grouping - it does not belong in a remediation list.
  const actionable = CHECKS.filter(function(c) {
    return ['Fail','Warning'].includes(c.result) && !isAccepted(resultKey(c)) && !c.error;
  });

  // A single CheckId can emit members with different Result/Severity/Finding (e.g.
  // MET-MDO010's High Fail for the toggle vs. its Medium Warning for tagging) - the
  // group's displayed name/result/severity/finding/primaryKey must come from the
  // single highest-priority member, not whichever happens to be first in iteration
  // order. Same result-then-severity-weight ranking used for card sorting above
  // (Fail before Warning, then higher SEV_WEIGHT first).
  const TOP5_RESULT_RANK = {Fail:0, Warning:1};
  const groupOrder = [];
  const groups = {};
  actionable.forEach(function(c) {
    let group = groups[c.checkId];
    if (!group) {
      group = { checkId: c.checkId, name: c.name, result: c.result, severity: c.severity, finding: c.finding, primaryKey: resultKey(c), weight: 0, keys: [] };
      groups[c.checkId] = group;
      groupOrder.push(c.checkId);
    } else {
      const curRank = TOP5_RESULT_RANK[group.result] ?? 9;
      const newRank = TOP5_RESULT_RANK[c.result] ?? 9;
      const curWeight = SEV_WEIGHT[group.severity] || 0;
      const newWeight = SEV_WEIGHT[c.severity] || 0;
      if (newRank < curRank || (newRank === curRank && newWeight > curWeight)) {
        group.name = c.name;
        group.result = c.result;
        group.severity = c.severity;
        group.finding = c.finding;
        group.primaryKey = resultKey(c);
      }
    }
    group.weight += (SEV_WEIGHT[c.severity] || 0);
    group.keys.push(resultKey(c));
  });

  const top5 = groupOrder.map(function(id) { return groups[id]; })
    .sort(function(a, b) { return b.weight - a.weight; })
    .slice(0, 5);

  const body = document.getElementById('top5-body');
  body.innerHTML = '';
  if (!top5.length) {
    const p = document.createElement('div');
    p.style.cssText = 'padding:16px;color:var(--text2);font-size:var(--fs-xs)';
    // An empty report ran no checks at all - "No failing or warning checks" implies a
    // clean assessment, which contradicts the "No data" state shown in the score banner.
    p.textContent = IS_EMPTY_REPORT ? 'No check results in this report.' : 'No failing or warning checks.';
    body.appendChild(p);
    return;
  }
  top5.forEach(function(group, i) {
    const primaryKey = group.primaryKey;
    const count = group.keys.length;
    // Same CheckId fallback used for the card title (G-14 item 6) - a check with no
    // usable Name must not render a blank Top 5 row.
    const nameText = (group.name || group.checkId) + (count > 1 ? ' (' + count + ' ' + getAggregationNoun(group.checkId) + ')' : '');
    const row = document.createElement('div');
    row.className = 'top5-row';
    row.dataset.resultKey = primaryKey;
    // Keyboard-reachable click target, same role/tabindex/keydown pattern already used
    // for .card-header and the tabs elsewhere in this file.
    row.setAttribute('role', 'button');
    row.setAttribute('tabindex', '0');
    row.setAttribute('aria-label', 'Jump to check ' + group.checkId);
    // G-13 item 8: no result badge here - every row is already a Fail or a Warning by
    // construction (see the `actionable` filter above), so a second badge repeating that
    // is pure noise in a remediation list. One severity chip is enough.
    row.innerHTML =
      '<div class="top5-rank">' + (i+1) + '</div>' +
      '<div>' +
        '<div class="top5-id">' + esc(group.checkId) + '</div>' +
        '<div class="top5-name">' + esc(nameText) + '</div>' +
      '</div>' +
      '<div class="top5-finding" dir="auto">' + fmtFinding(group.finding) + '</div>' +
      '<span class="sev-pill sev-' + slug(sevOf(group.severity)) + '">' + esc(sevOf(group.severity).toUpperCase()) + '</span>';
    // The Top 5 tab hides #cards-container in applyFilters(), so scrollIntoView() on a
    // display:none card can't reach or expand it - switch to the All tab first, same as
    // the Controls-row jump handler in renderControlsRef() already does.
    const jumpToCard = function() {
      switchToTab('All');
      const card = cardMap[primaryKey];
      if (!card) return;
      ensureGroupExpanded(card);
      const body = card.querySelector('.card-body');
      const chev = card.querySelector('.card-chevron');
      if (!body.classList.contains('open')) {
        body.classList.add('open');
        chev.classList.add('open');
      }
      card.scrollIntoView({behavior:'smooth', block:'center'});
    };
    row.addEventListener('click', jumpToCard);
    row.addEventListener('keydown', function(e) {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); jumpToCard(); }
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
      const key = resultKey(c);
      const accepted = isAccepted(key);
      const hasError = !!c.error;
      // hasError wins over accepted - see the matching note in createCard().
      const resultDisplay = hasError ? 'Error' : (accepted ? 'Accepted' : c.result);
      const rbClass = 'rb-' + (hasError ? 'error' : (accepted ? 'accepted' : slug(c.result)));
      const desc = CONTROLS_META[c.checkId] || c.name;
      // role="button"/tabindex on a <tr> keeps this row a valid table row while making
      // it a keyboard-reachable click target - same reasoning as .top5-row above; a
      // wrapping focusable element would break the existing table cell layout.
      html += '<tr class="ctrl-row" data-checkid="' + esc(c.checkId) + '" data-result-key="' + esc(key) + '" title="Click to jump to check card" role="button" tabindex="0" aria-label="Jump to check ' + esc(c.checkId) + '">';
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
    const jumpToCard = function() {
      const key = row.dataset.resultKey;
      switchToTab('All');
      const card = cardMap[key];
      if (card) {
        ensureGroupExpanded(card);
        card.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    };
    row.addEventListener('click', jumpToCard);
    row.addEventListener('keydown', function(e) {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); jumpToCard(); }
    });
  });
}

// Roving tabindex per WAI-ARIA tab pattern: exactly one tab is in the Tab order at a time
// (tabindex=0), the rest are tabindex=-1 and reached only via arrow keys once the tablist
// itself has focus.
function activateTab(target) {
  document.querySelectorAll('.tab').forEach(function(t) {
    const isTarget = t === target;
    t.classList.toggle('active', isTarget);
    t.setAttribute('aria-selected', isTarget ? 'true' : 'false');
    t.setAttribute('tabindex', isTarget ? '0' : '-1');
  });
  activeTab = target.dataset.tab;
  applyFilters();
}

function switchToTab(tabName) {
  const target = document.querySelector('.tab[data-tab="' + tabName + '"]');
  if (target) activateTab(target);
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
    // #result-count lives inside .filters, which is hidden on this tab (no search/severity/
    // result filtering applies to the fixed reference table) - writing "N controls" into it
    // here was dead output, invisible to sighted users and absent from the accessibility
    // tree alike. Clear it instead of leaving whatever the previously active tab wrote, so a
    // future unhide of .filters can never surface a stale count. The total is already
    // visible and announced via the "All Controls" tab's own tc-controls badge, updated
    // below (G-14 item 4).
    document.getElementById('result-count').textContent = '';
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
  const groupVisibleCounts = {};
  allCards.forEach(function(card) {
    const cat   = card.dataset.category;
    const isAcc = card.dataset.accepted === '1';

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

    const show = inScope && cardMatchesFilters(card, search, sevFilter, resFilter);
    card.style.display = show ? '' : 'none';
    if (show) {
      visible++;
      const g = card.dataset.group;
      groupVisibleCounts[g] = (groupVisibleCounts[g] || 0) + 1;
    }
  });
  updateGroupHeaders(groupVisibleCounts);

  document.getElementById('no-results').style.display = visible === 0 ? '' : 'none';
  document.getElementById('result-count').textContent = 'Showing ' + visible + ' of ' + inScopeTotal + ' checks';
  updateTabCounts();
}

// Whether a card matches the current search/severity/result filters, independent of which
// tab is active - shared by applyFilters (per-tab visibility) and updateTabCounts (per-category
// badges), so the two can never disagree about what "currently matching" means.
function cardMatchesFilters(card, search, sevFilter, resFilter) {
  const result = card.dataset.result;
  const isErr  = card.dataset.error === '1';
  const sev    = card.dataset.sev;
  const sText  = card.dataset.search || '';

  let match = true;
  if (sevFilter) match = sev === sevFilter;
  // Error is its own bucket, mutually exclusive with every Result-based option, matching the
  // ERROR badge on the card itself and the summary/donut counts above.
  if (match && resFilter) match = resFilter === 'Error' ? isErr : (result === resFilter && !isErr);
  if (match && search)    match = sText.includes(search);
  return match;
}

function updateTabCounts() {
  const search    = document.getElementById('search').value.toLowerCase();
  const sevFilter = document.getElementById('sev-filter').value;
  const resFilter = document.getElementById('result-filter').value;

  const counts = {All:0, MDO:0, EXO:0, Teams:0, Accepted:0};
  allCards.forEach(function(card) {
    if (!cardMatchesFilters(card, search, sevFilter, resFilter)) return;
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

const tabEls = Array.from(document.querySelectorAll('.tab'));
tabEls.forEach(function(tab, i) {
  tab.addEventListener('click', function() { activateTab(this); });
  tab.addEventListener('keydown', function(e) {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); activateTab(this); return; }
    let nextIndex = null;
    if (e.key === 'ArrowRight' || e.key === 'ArrowDown')      nextIndex = (i + 1) % tabEls.length;
    else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp')    nextIndex = (i - 1 + tabEls.length) % tabEls.length;
    else if (e.key === 'Home')                                nextIndex = 0;
    else if (e.key === 'End')                                 nextIndex = tabEls.length - 1;
    if (nextIndex !== null) {
      e.preventDefault();
      const next = tabEls[nextIndex];
      next.focus();
      activateTab(next);
    }
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
let pendingKey = null;
let modalTriggerEl = null;

function closeModal() {
  document.getElementById('modal-overlay').classList.remove('open');
  pendingKey = null;
  // The trigger button survives an Escape/Cancel close, but Confirm's rebuildCard()
  // replaces it, and accepting the risk can also remove the card from view entirely
  // (it moves out of the current tab's scope) - fall back to the active tab, always
  // present and visible, rather than focusing a detached or hidden element.
  let target = modalTriggerEl;
  if (!target || !document.body.contains(target) || target.offsetParent === null) {
    target = document.querySelector('.tab.active');
  }
  if (target) target.focus();
  modalTriggerEl = null;
}

function getModalFocusable() {
  return Array.from(document.querySelectorAll('#modal-overlay .modal textarea, #modal-overlay .modal button'))
    .filter(function(el) { return !el.disabled; });
}

document.addEventListener('click', function(e) {
  const acceptBtn = e.target.closest('.btn-accept');
  if (acceptBtn) {
    pendingKey = acceptBtn.dataset.resultKey;
    modalTriggerEl = acceptBtn;
    const pendingCheck = CHECKS.find(function(c){ return resultKey(c) === pendingKey; });
    const label = pendingCheck
      ? pendingCheck.checkId + (pendingCheck.affectedObject ? ' (' + pendingCheck.affectedObject + ')' : '')
      : acceptBtn.dataset.checkid;
    document.getElementById('modal-desc').textContent = 'Accepting risk for ' + label + '. Provide a business justification.';
    document.getElementById('modal-text').value = '';
    document.getElementById('modal-confirm').disabled = true;
    document.getElementById('modal-overlay').classList.add('open');
    setTimeout(function(){ document.getElementById('modal-text').focus(); }, 50);
  }

  const undoBtn = e.target.closest('.btn-undo');
  if (undoBtn) {
    const key = undoBtn.dataset.resultKey;
    clearAccepted(key);
    rebuildCard(key);
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
  closeModal();
});

document.getElementById('modal-confirm').addEventListener('click', function() {
  if (!pendingKey) return;
  let just = document.getElementById('modal-text').value.trim();
  if (just.length > JUSTIFICATION_MAX_LENGTH) just = just.slice(0, JUSTIFICATION_MAX_LENGTH);
  const key = pendingKey;
  setAccepted(key, just);
  rebuildCard(key);
  updateTabCounts();
  recalcScore();
  renderTop5();
  applyFilters();
  closeModal();
});

document.getElementById('modal-overlay').addEventListener('click', function(e) {
  if (e.target === this) { document.getElementById('modal-cancel').click(); }
});

document.getElementById('modal-overlay').addEventListener('keydown', function(e) {
  if (!this.classList.contains('open')) return;
  if (e.key === 'Escape') {
    e.preventDefault();
    document.getElementById('modal-cancel').click();
    return;
  }
  if (e.key === 'Tab') {
    const focusable = getModalFocusable();
    if (focusable.length === 0) return;
    const first = focusable[0];
    const last  = focusable[focusable.length - 1];
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault(); last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault(); first.focus();
    }
  }
});

function rebuildCard(key) {
  const check = CHECKS.find(function(c){ return resultKey(c) === key; });
  if (!check) return;
  const oldCard = cardMap[key];
  if (!oldCard) return;
  const newCard = createCard(check);
  // card.dataset.group is the underlying Result, unaffected by accept/undo (see its
  // assignment in createCard()), so the rebuilt card always belongs in the exact DOM
  // position (same card-group-body) the old one did - replaceChild is sufficient, with
  // no re-parenting into a different group needed.
  oldCard.parentNode.replaceChild(newCard, oldCard);
  cardMap[key] = newCard;
  const idx = allCards.indexOf(oldCard);
  if (idx !== -1) allCards[idx] = newCard;
}

// ── Sticky toolbar-height sync ──────────────────────────────────────
// .card-group-header's sticky offset (--toolbar-h) must track the toolbar's real
// rendered height, not a hardcoded value - the toolbar wraps to two rows at narrow
// widths (the report's documented 1024px minimum), and a stale offset lets the
// taller wrapped toolbar cover the sticky group header instead of sitting above it.
(function() {
  const toolbarEl = document.querySelector('.toolbar');
  if (!toolbarEl) return;
  const syncToolbarHeight = function() {
    document.documentElement.style.setProperty('--toolbar-h', toolbarEl.offsetHeight + 'px');
  };
  syncToolbarHeight();
  if (typeof ResizeObserver !== 'undefined') {
    new ResizeObserver(syncToolbarHeight).observe(toolbarEl);
  } else {
    window.addEventListener('resize', syncToolbarHeight);
  }
})();

// ── Init ─────────────────────────────────────────────────────────
(function() {
  const LS_SCORE_KEY = 'MET_score_' + TENANT_ID;
  // G-copilot item 3: an empty report's INITIAL_SCORE is a placeholder (0), not an
  // observed score - comparing it against a real cached score would produce a
  // misleading delta next to the "No data" banner, and caching it would poison the
  // comparison for the next real run. Skip the cache read/write entirely.
  if (!IS_EMPTY_REPORT) {
    const prev = lsGet(LS_SCORE_KEY);
    // Number(...) is strict - Number("40garbage") is NaN - unlike parseInt, which
    // would parse "40garbage" as 40 and treat a corrupted cache value as valid.
    const prevScore = prev !== null ? Number(prev) : NaN;
    if (Number.isFinite(prevScore) && prevScore >= 0 && prevScore <= 100) {
      const delta = INITIAL_SCORE - prevScore;
      if (delta !== 0) {
        const el = document.getElementById('score-delta');
        if (el) {
          el.textContent = (delta > 0 ? '+' : '') + delta;
          el.className = 'score-delta ' + (delta > 0 ? 'delta-up' : 'delta-down');
        }
        // G-13 item 7: the delta previously appeared with no stated baseline. Labelled here,
        // not dropped, since "vs. last viewed run" is literally what INITIAL_SCORE is being
        // compared against - the score cached in this browser's localStorage the last time a
        // report for this tenant was opened.
        const captionEl = document.getElementById('score-delta-caption');
        if (captionEl) captionEl.style.display = '';
      }
    }
    lsSet(LS_SCORE_KEY, INITIAL_SCORE);
  }
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

                New-METRestrictedFile -Path $dest
                $html | Set-Content -LiteralPath $dest -Encoding UTF8
                Write-Host "  Report written: $dest" -ForegroundColor Cyan
                $writtenFiles.Add((Get-Item -LiteralPath $dest))
                Write-Verbose "HTML report written to $dest"
                if ($assessmentOutputFolder -and -not $assessmentFolderAnnounced) {
                  Write-Verbose "Assessment output folder: $assessmentOutputFolder"
                  $assessmentFolderAnnounced = $true
                }

                if (-not $NoLaunch) {
                    # Start-Process has no handler on a headless Linux host and throws.
                    # Swallowing it into Write-Verbose left the user with no path and no
                    # browser, which reads as the command having done nothing at all.
                    try {
                        Start-Process $dest
                    }
                    catch {
                        Write-Warning "Could not open the report automatically. Open it manually: $dest"
                    }
                }
            } else {
                $html
            }
        }

        if ($PassThru) { return $writtenFiles.ToArray() }
    }
}
