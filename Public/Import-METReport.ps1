function Import-METReport {
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

    if (-not $report.PSObject.Properties['checks']) {
        throw "'$Path' is not a MET report - it has no 'checks' array. Reports are produced by Get-METReport -Format JSON."
    }

    foreach ($check in @($report.checks)) {
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
