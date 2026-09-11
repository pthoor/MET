function Import-METReport {
    <#
    .SYNOPSIS
        Reads a MET JSON report back into check result objects, without losing tenant provenance.

    .DESCRIPTION
        Reads a report file written by Get-METReport -Format JSON (or -Format All) and rebuilds
        one MET.CheckResult object per saved check, restoring PascalCase property names
        (CheckId, Category, Result, ...) rather than the camelCase ConvertFrom-Json would
        otherwise yield straight off the JSON.

        The report's tenant, run timestamp, and authentication metadata are folded into each
        result's Metadata (as METRunTenant, METRunTimestamp, and METRunAuthentication) rather
        than kept at the collection level, so
        that provenance survives being filtered or concatenated with Where-Object or by piping
        two imports together - a collection-level stamp would be lost the moment that happened.
        This lets a saved report be piped straight back into Get-METReport (to regenerate an
        HTML/console view, or to re-run the cross-tenant provenance check) without re-running
        the assessment itself. A path that is missing, not valid JSON, or valid JSON without a
        'checks' array (i.e. not a MET report) throws a descriptive error rather than returning
        an empty or partial result set.

    .PARAMETER Path
        Path to a JSON report file previously written by Get-METReport -Format JSON or -Format All.

    .OUTPUTS
        MET.CheckResult[]. One object per check recorded in the report, with the same shape
        Invoke-METAssessment produces, so it can be piped into Get-METReport or filtered like
        any other MET result collection.

    .EXAMPLE
        Import-METReport -Path ./assessments/contoso-2026-06-01/MET-report.json

        Reads a previously saved report back into result objects.

    .EXAMPLE
        Import-METReport -Path ./assessments/contoso-2026-06-01/MET-report.json | Get-METReport -Format HTML -OutputPath ./assessments/contoso-2026-06-01/

        Regenerates the HTML report from a saved JSON file - for example after an HTML rendering
        fix ships - without needing a live tenant connection or re-running the assessment.

    .EXAMPLE
        $old = Import-METReport -Path ./assessments/contoso-2026-05-01/MET-report.json
        $new = Import-METReport -Path ./assessments/contoso-2026-06-01/MET-report.json
        Compare-Object $old $new -Property CheckId, Result

        Compares two saved runs for the same tenant to see which checks changed result between
        assessments.

    .EXAMPLE
        Get-ChildItem ./assessments -Filter 'MET-report.json' -Recurse |
            ForEach-Object { Import-METReport -Path $_.FullName }

        Re-hydrates every saved report under an assessments folder in one pass, for example to
        build a historical view across many past runs.
    #>
    [CmdletBinding(PositionalBinding = $false)]
    [OutputType('MET.CheckResult')]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Report file not found: '$Path'"
    }

    try {
        $report = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "'$Path' is not valid JSON: $($_.Exception.Message)"
    }

    if (-not $report.PSObject.Properties['checks'] -or $null -eq $report.checks -or
        $report.checks -isnot [array]) {
        throw "'$Path' is not a MET report - it has no 'checks' array. Reports are produced by Get-METReport -Format JSON."
    }

    $runTimestamp = $null
    if ($report.PSObject.Properties['runTimestamp'] -and $report.runTimestamp) {
        $runTimestamp = [datetime]::Parse(
            $report.runTimestamp,
            [cultureinfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor
                [System.Globalization.DateTimeStyles]::AssumeUniversal)
    }

    foreach ($check in $report.checks) {
        # Provenance travels on every result rather than alongside the collection, because
        # Get-METReport reads it per-result and a collection-level stamp would be lost the
        # moment someone filtered or concatenated the results (e.g. Where-Object, or piping
        # two imports together).
        $metadata = @{}
        if ($check.PSObject.Properties['metadata'] -and $check.metadata) {
            foreach ($property in $check.metadata.PSObject.Properties) {
                $metadata[$property.Name] = $property.Value
            }
        }
        if ($report.PSObject.Properties['tenant'] -and $report.tenant) {
            $metadata['METRunTenant'] = [string]$report.tenant
        }
        if ($runTimestamp) {
            $metadata['METRunTimestamp'] = $runTimestamp
        }
        if ($report.PSObject.Properties['authentication'] -and $report.authentication) {
            # Left as-is (camelCase, straight off the JSON) rather than reshaped into the
            # PascalCase $script:METSessionInfo carries for a live session - Get-METReport
            # reads each shape explicitly by name. Normalizing here would be the same
            # case-insensitive-access accident C-20 exists to fix, just moved one function over.
            $metadata['METRunAuthentication'] = $report.authentication
        }

        $timestamp = $null
        if ($check.timestamp) {
            $timestamp = [datetime]::Parse(
                $check.timestamp,
                [cultureinfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor
                    [System.Globalization.DateTimeStyles]::AssumeUniversal)
        }

        [PSCustomObject]@{
            PSTypeName     = 'MET.CheckResult'
            CheckId        = [string]$check.checkId
            Category       = [string]$check.category
            Name           = [string]$check.name
            Result         = [string]$check.result
            Severity       = [string]$check.severity
            Score          = $check.score
            AffectedObject = [string]$check.affectedObject
            Finding        = [string]$check.finding
            Recommendation = [string]$check.recommendation
            ReferenceUrl   = [string]$check.referenceUrl
            Timestamp      = $timestamp
            Error          = $check.error
            Metadata       = $metadata
        }
    }
}
