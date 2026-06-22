function Invoke-METTriage {
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet('MDO','EXO','Teams')]
        [string[]] $Category,

        [Parameter()]
        [string[]] $CheckId,

        [Parameter()]
        [string[]] $ExcludeCheckId,

        [Parameter()]
        [string] $DelegatedOrganization,

        [Parameter()]
        [switch] $PassThru,

        [Parameter()]
        [switch] $ListChecks,

        [Parameter()]
        [switch] $Detailed
    )

    $checksRoot = Join-Path $PSScriptRoot '..' 'Checks'

    $checkFiles = Get-ChildItem -Path $checksRoot -Recurse -Filter 'MET-*.ps1' |
        Sort-Object Name

    if ($Category) {
        $checkFiles = $checkFiles | Where-Object {
            $Category -contains $_.Directory.Name
        }
    }

    if ($CheckId) {
        $checkFiles = $checkFiles | Where-Object {
            $id = ($_.BaseName -split '-')[0..1] -join '-'
            $CheckId -contains $id
        }
    }

    if ($ExcludeCheckId) {
        $checkFiles = $checkFiles | Where-Object {
            $id = ($_.BaseName -split '-')[0..1] -join '-'
            $ExcludeCheckId -notcontains $id
        }
    }

    if ($ListChecks) {
        return $checkFiles | ForEach-Object {
            $parts = $_.BaseName -split '-', 3
            [PSCustomObject]@{
                CheckId  = "$($parts[0])-$($parts[1])"
                Category = $_.Directory.Name
                Script   = $_.Name
            }
        }
    }

    # Pre-fetch shared context. Check scripts access $METContext via the
    # scriptblock wrapper below ($METContext injected as a named parameter).
    $METContext = @{
        AcceptedDomains = @()
        GroupMembers    = @{}    # keyed by group identity; populated lazily by checks
        AllMailboxes    = $null  # populated lazily by MDO008; reused by any future coverage check
    }

    Write-Progress -Activity 'MET Triage' -Status 'Initializing — fetching accepted domains...' `
        -PercentComplete 0 -Id 1

    try {
        $METContext.AcceptedDomains = @(Get-AcceptedDomain -ErrorAction Stop)
        Write-Verbose "Pre-fetched $($METContext.AcceptedDomains.Count) accepted domain(s)"
    }
    catch {
        Write-Warning "Could not pre-fetch accepted domains: $_"
    }

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    $totalChecks = @($checkFiles).Count
    $currentIndex = 0

    foreach ($file in $checkFiles) {
        $currentIndex++
        $checkIdDisplay = ($file.BaseName -split '-' | Select-Object -First 2) -join '-'
        Write-Progress -Activity 'MET Triage' -Status "$checkIdDisplay — $($file.BaseName)" `
            -PercentComplete ([int]($currentIndex / $totalChecks * 100)) `
            -CurrentOperation "Check $currentIndex of $totalChecks" -Id 1
        Write-Verbose "Running check: $($file.BaseName)"

        # Run the check script inside a scriptblock so that:
        #   1. $METContext is injected as a local variable the script can read.
        #   2. `return` inside the check script exits only this scriptblock,
        #      not Invoke-METTriage, avoiding the dot-source return-scope trap.
        #   3. Hashtable fields (e.g. GroupMembers) mutated by the check script
        #      persist across checks because hashtables are reference types.
        $checkPath = $file.FullName
        try {
            $checkResults = & {
                param([hashtable] $METContext)
                . $checkPath
            } $METContext

            if ($checkResults) {
                foreach ($r in $checkResults) {
                    if ($PassThru) { Write-Output $r } else { $results.Add($r) }
                }
            }
        }
        catch {
            $checkIdPart = ($file.BaseName -split '-' | Select-Object -First 2) -join '-'
            $errResult = [PSCustomObject]@{
                CheckId        = $checkIdPart
                Category       = $file.Directory.Name
                Name           = $file.BaseName
                Result         = 'Fail'
                Severity       = 'High'
                Score          = $null
                AffectedObject = 'N/A'
                Finding        = 'Check script failed to execute'
                Recommendation = ''
                ReferenceUrl   = ''
                Timestamp      = [datetime]::UtcNow
                Error          = $_.ToString()
            }
            if ($PassThru) { Write-Output $errResult } else { $results.Add($errResult) }
        }
    }

    Write-Progress -Activity 'MET Triage' -Completed -Id 1

    if ($PassThru) { return }

    if ($Detailed) {
        return $results.ToArray()
    }

    # Aggregate: collapse multiple per-policy / per-domain results for the same
    # CheckId into a single result, keeping per-item detail in the Finding text.
    # Use -Detailed to get the full per-object breakdown.
    $aggregated = [System.Collections.Generic.List[PSCustomObject]]::new()

    $groups = $results | Group-Object CheckId

    foreach ($group in $groups) {
        $items = @($group.Group)

        if ($items.Count -eq 1) {
            $aggregated.Add($items[0])
            continue
        }

        $failItems  = @($items | Where-Object Result -eq 'Fail')
        $warnItems  = @($items | Where-Object Result -eq 'Warning')
        $errorItems = @($items | Where-Object { $_.Error })

        if ($failItems.Count -eq 0 -and $warnItems.Count -eq 0 -and $errorItems.Count -eq 0) {
            # All pass / info / N/A — emit a single tidy pass result
            $first   = $items[0]
            $passItems = @($items | Where-Object Result -eq 'Pass')
            $passCount = $passItems.Count
            $noun    = Get-METAggregationNoun -CheckId $first.CheckId

            if ($passCount -gt 0) {
                $findingLines = $passItems | ForEach-Object { "$($_.AffectedObject): $($_.Finding)" }
                $aggregated.Add((New-METCheckResult `
                    -CheckId $first.CheckId -Category $first.Category -Name $first.Name `
                    -Result Pass -Severity $first.Severity `
                    -AffectedObject "All $passCount $noun" `
                    -Finding ($findingLines -join "`n") `
                    -Recommendation $first.Recommendation `
                    -ReferenceUrl $first.ReferenceUrl))
            } else {
                $aggregated.Add($items[0])
            }
            continue
        }

        # Determine which items are noteworthy
        $badItems    = if ($failItems.Count -gt 0) { $failItems } elseif ($warnItems.Count -gt 0) { $warnItems } else { $errorItems }
        $worstResult = if ($failItems.Count -gt 0) { 'Fail' } elseif ($warnItems.Count -gt 0) { 'Warning' } else { 'Fail' }
        $first       = $items[0]
        $noun        = Get-METAggregationNoun -CheckId $first.CheckId

        $findingLines = $badItems | ForEach-Object { "$($_.AffectedObject): $($_.Finding)" }

        $aggregated.Add((New-METCheckResult `
            -CheckId $first.CheckId -Category $first.Category -Name $first.Name `
            -Result $worstResult -Severity $first.Severity `
            -AffectedObject "$($badItems.Count) of $($items.Count) $noun" `
            -Finding ($findingLines -join "`n") `
            -Recommendation $first.Recommendation `
            -ReferenceUrl $first.ReferenceUrl))
    }

    return $aggregated.ToArray()
}

function Get-METAggregationNoun {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $CheckId)

    switch -Regex ($CheckId) {
        'MET-EXO00[1-3]' { return 'domains' }
        'MET-EXO004'      { return 'quarantine policies' }
        default            { return 'policies' }
    }
}
