function Get-METWorstSeverity {
    # Returns the highest-weighted severity in a set. Used when Invoke-METTriage
    # collapses a check's per-domain/per-policy results into one summary object:
    # the aggregate must inherit the severity of the worst finding it represents,
    # not of whichever item happened to be emitted first. Inheriting Informational
    # (weight 0) from a leading NotApplicable result would drop the aggregate out
    # of the posture score entirely.
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)] [AllowNull()] [AllowEmptyCollection()] [string[]] $Severity
    )

    begin {
        $rank = @{ Informational = 0; Low = 1; Medium = 2; High = 3; Critical = 4 }
        $best = $null
    }

    process {
        foreach ($s in @($Severity)) {
            if ([string]::IsNullOrWhiteSpace($s)) { continue }
            $name = $rank.Keys | Where-Object { $_ -eq $s } | Select-Object -First 1
            if (-not $name) { continue }
            if ($null -eq $best -or $rank[$name] -gt $rank[$best]) { $best = $name }
        }
    }

    end {
        if ($best) { return $best }
        return 'Informational'
    }
}
