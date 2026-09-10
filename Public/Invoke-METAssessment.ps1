function Invoke-METAssessment {
    [CmdletBinding(PositionalBinding = $false)]
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

    # Every MDO and EXO check needs Exchange Online, and Teams001/002/004 call
    # Exchange-hosted cmdlets too. Without a session the run took 95 seconds to
    # produce 51 results scoring 11/Critical, 45 of them errors - an artifact that
    # reads as a genuine assessment. Fail at the door instead.
    if (-not (Get-ConnectionInformation -ErrorAction SilentlyContinue)) {
        $PSCmdlet.ThrowTerminatingError(
            [System.Management.Automation.ErrorRecord]::new(
                [System.InvalidOperationException]::new(
                    'Not connected to Exchange Online. Run Connect-METSession first.'),
                'METNotConnected',
                [System.Management.Automation.ErrorCategory]::ConnectionError,
                $null))
    }

    $checksRoot = Join-Path $PSScriptRoot '..' 'Checks'

    $allCheckFiles = Get-ChildItem -LiteralPath $checksRoot -Recurse -Filter 'MET-*.ps1' |
        Sort-Object Name
    $checkFiles = $allCheckFiles

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

    $knownCheckIds = @($allCheckFiles | ForEach-Object { ($_.BaseName -split '-')[0..1] -join '-' })

    foreach ($requested in @($CheckId) + @($ExcludeCheckId)) {
        if ($requested -and $knownCheckIds -notcontains $requested) {
            Write-Warning "'$requested' matched no check. Run Get-METCheck to list the available check IDs (they look like 'MET-EXO010', including the MET- prefix)."
        }
    }

    if (@($checkFiles).Count -eq 0) {
        Write-Warning 'No checks matched the given -Category/-CheckId/-ExcludeCheckId combination. Nothing will run. Run Get-METCheck to list the available checks.'
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
        TenantName      = ''
    }

    Write-Progress -Activity 'MET Assessment' -Status 'Initializing - fetching accepted domains...' `
        -PercentComplete 0 -Id 1

    try {
        $METContext.AcceptedDomains = @(Get-AcceptedDomain -ErrorAction Stop)
        Write-Verbose "Pre-fetched $($METContext.AcceptedDomains.Count) accepted domain(s)"

        $defaultDomain = $METContext.AcceptedDomains | Where-Object { $_.Default -eq $true } | Select-Object -First 1
        if ($defaultDomain -and $defaultDomain.DomainName) {
            $METContext.TenantName = [string]$defaultDomain.DomainName
        }
    }
    catch {
        Write-Warning "Could not pre-fetch accepted domains: $_"
    }

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    $totalChecks = @($checkFiles).Count
    $currentIndex = 0

    $stampProvenance = {
        param($Result, [string] $Tenant)
        if (-not $Tenant) { return $Result }
        if ($null -eq $Result.Metadata) {
            $Result.Metadata = @{ METRunTenant = $Tenant }
        }
        elseif (-not $Result.Metadata.ContainsKey('METRunTenant')) {
            $Result.Metadata['METRunTenant'] = $Tenant
        }
        $Result
    }

    foreach ($file in $checkFiles) {
        $currentIndex++
        $checkIdDisplay = ($file.BaseName -split '-' | Select-Object -First 2) -join '-'
        Write-Progress -Activity 'MET Assessment' -Status "$checkIdDisplay - $($file.BaseName)" `
            -PercentComplete ([int]($currentIndex / $totalChecks * 100)) `
            -CurrentOperation "Check $currentIndex of $totalChecks" -Id 1
        Write-Verbose "Running check: $($file.BaseName)"

        # Run the check script inside a scriptblock so that:
        #   1. $METContext is injected as a local variable the script can read.
        #   2. `return` inside the check script exits only this scriptblock,
        #      not Invoke-METAssessment, avoiding the dot-source return-scope trap.
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
                    $r = & $stampProvenance $r $METContext.TenantName
                    if ($PassThru) { Write-Output $r } else { $results.Add($r) }
                }
            }
            else {
                $checkName = [regex]::Replace((($file.BaseName -split '-')[-1]), '(?<=[a-z0-9])(?=[A-Z])', ' ')
                $placeholder = New-METCheckResult -CheckId $checkIdDisplay -Category $file.Directory.Name `
                    -Name $checkName -Result NotApplicable -Severity Informational `
                    -AffectedObject 'Tenant' `
                    -Finding 'The check ran without error but produced no result, which usually means the cmdlet it reads returned no objects. Nothing was asserted about this control.' `
                    -Recommendation 'Confirm the relevant policies exist in the tenant, and that the account running MET can enumerate them.'
                $placeholder = & $stampProvenance $placeholder $METContext.TenantName
                if ($PassThru) { Write-Output $placeholder } else { $results.Add($placeholder) }
            }
        }
        catch {
            $checkIdPart = ($file.BaseName -split '-' | Select-Object -First 2) -join '-'
            $errResult = [PSCustomObject]@{
                PSTypeName     = 'MET.CheckResult'
                CheckId        = $checkIdPart
                Category       = $file.Directory.Name
                Name           = $file.BaseName
                Result         = 'Fail'
                Severity       = 'High'
                # Must be 0, not $null. Get-METReport only scores results with a
                # non-null Score, so a null here silently removes every crashed
                # check from the posture index - a run where half the checks threw
                # would report a perfect score above a table of its own failures.
                Score          = 0
                AffectedObject = 'N/A'
                Finding        = 'Check script failed to execute'
                Recommendation = ''
                ReferenceUrl   = ''
                Timestamp      = [datetime]::UtcNow
                Error          = $_.ToString()
                Metadata       = $null
            }
            $errResult = & $stampProvenance $errResult $METContext.TenantName
            if ($PassThru) { Write-Output $errResult } else { $results.Add($errResult) }
        }
    }

    Write-Progress -Activity 'MET Assessment' -Completed -Id 1

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
            # All pass / info / N/A - emit a single tidy summary result. Info-only
            # checks (e.g. MET-MDO014's healthy case) are summarised the same way
            # Pass results are, so no item is silently dropped.
            $first     = $items[0]
            $passItems = @($items | Where-Object Result -eq 'Pass')
            $infoItems = @($items | Where-Object Result -eq 'Info')
            $noun      = Get-METAggregationNoun -CheckId $first.CheckId

            $summaryItems  = @($passItems) + @($infoItems)
            $summaryResult = if ($passItems.Count -gt 0) { 'Pass' } else { 'Info' }

            if ($summaryItems.Count -gt 0) {
                $findingLines = $summaryItems | ForEach-Object { "$($_.AffectedObject): $($_.Finding)" }
                $aggregated.Add((New-METCheckResult `
                    -CheckId $first.CheckId -Category $first.Category -Name $first.Name `
                    -Result $summaryResult -Severity (Get-METWorstSeverity -Severity ($summaryItems | ForEach-Object { $_.Severity })) `
                    -AffectedObject "All $($summaryItems.Count) $noun" `
                    -Finding ($findingLines -join "`n") `
                    -Recommendation $first.Recommendation `
                    -ReferenceUrl $first.ReferenceUrl `
                    -Metadata $first.Metadata))
            } else {
                $aggregated.Add($items[0])
            }
            continue
        }

        # Every noteworthy item: failures, warnings, and any item carrying an Error
        # (a High "could not assess" NotApplicable/Info among them). An errored item whose
        # Result kept it out of the fail/warn sets still contributes its severity and its
        # Finding - dropping the severity let a High unassessed result co-occurring with a
        # Medium warning score the aggregate at Medium, hiding the more serious signal.
        $noteworthyItems = @($failItems) + @($warnItems) +
            @($errorItems | Where-Object { $_ -notin $failItems -and $_ -notin $warnItems })
        $worstResult = if ($failItems.Count -gt 0) { 'Fail' } elseif ($warnItems.Count -gt 0) { 'Warning' } else { 'Fail' }
        $first       = $items[0]
        $noun        = Get-METAggregationNoun -CheckId $first.CheckId

        # Severity must come from the noteworthy items, not from $items[0]. Checks that
        # emit one result per domain/policy routinely emit an Informational or
        # NotApplicable result first - MET-EXO001 does exactly this for the tenant's
        # .mail.onmicrosoft.com routing domain. Inheriting that severity stamps the
        # aggregate Informational, whose scoring weight is 0, which removes the finding
        # from both the numerator and the denominator of the posture score: a real DMARC
        # failure would disappear from the score entirely.
        $worstSeverity = Get-METWorstSeverity -Severity ($noteworthyItems | ForEach-Object { $_.Severity })

        $findingLines = $noteworthyItems | ForEach-Object { "$($_.AffectedObject): $($_.Finding)" }
        $errorMessage = @($errorItems | ForEach-Object Error | Where-Object { $_ }) -join "`n"

        $aggregated.Add((New-METCheckResult `
            -CheckId $first.CheckId -Category $first.Category -Name $first.Name `
            -Result $worstResult -Severity $worstSeverity `
            -AffectedObject "$($noteworthyItems.Count) of $($items.Count) $noun" `
            -Finding ($findingLines -join "`n") `
            -Recommendation $first.Recommendation `
            -ReferenceUrl $first.ReferenceUrl `
            -ErrorMessage $errorMessage `
            -Metadata $first.Metadata))
    }

    return $aggregated.ToArray()
}

function Get-METAggregationNoun {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $CheckId)

    switch -Regex ($CheckId) {
        'MET-EXO00[1-3]' { return 'domains' }
        'MET-EXO004'      { return 'quarantine policies' }
        'MET-EXO018'      { return 'remote domains' }
        'MET-EXO020'      { return 'connection filter policies' }
        'MET-EXO022'      { return 'sharing policies' }
        'MET-MDO014'      { return 'groups' }
        default            { return 'policies' }
    }
}
