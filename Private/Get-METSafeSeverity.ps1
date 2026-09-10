function Get-METSafeSeverity {
    # Get-METCheckWeight has a ValidateSet, so a result carrying a null, empty or
    # unrecognised Severity throws a terminating error inside the scoring loop and
    # no report is produced at all - one malformed result destroys the whole
    # deliverable, including the checks that ran correctly. Normalise here instead
    # so an unknown severity degrades to zero weight rather than aborting the run.
    [CmdletBinding()]
    param(
        [AllowNull()] [AllowEmptyString()] [string] $Severity
    )

    $known = @('Critical', 'High', 'Medium', 'Low', 'Informational')

    if ([string]::IsNullOrWhiteSpace($Severity)) { return 'Informational' }

    $match = $known | Where-Object { $_ -eq $Severity } | Select-Object -First 1
    if ($match) { return $match }

    Write-Verbose "Unrecognised severity '$Severity' treated as Informational for scoring."
    return 'Informational'
}
