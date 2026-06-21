$cutoff = (Get-Date).ToUniversalTime().AddDays(-90)

$allEntries = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($listType in @('Sender','Url','FileHash')) {
    try {
        $entries = Get-TenantAllowBlockListItems -ListType $listType -ErrorAction Stop
        foreach ($e in $entries) { $allEntries.Add($e) }
    }
    catch {
        Write-Verbose "Could not retrieve TABL entries for type '$listType': $_"
    }
}

if ($allEntries.Count -eq 0) {
    New-METCheckResult -CheckId 'MET-EXO005' -Category EXO -Name 'Tenant Allow/Block List' `
        -Result Info -Severity Low -AffectedObject 'Tenant Allow/Block List' `
        -Finding 'No entries found in the Tenant Allow/Block List' `
        -Recommendation 'No action required. If you expect entries to be present, verify permissions (Security Reader or higher).' `
        -ReferenceUrl 'https://aka.ms/tabl'
    return
}

$allowEntries  = $allEntries | Where-Object { $_.Action -eq 'Allow' }
$blockEntries  = $allEntries | Where-Object { $_.Action -eq 'Block' }

$staleAllows = $allowEntries | Where-Object {
    $_.ExpirationDate -and [datetime]$_.ExpirationDate -lt (Get-Date).ToUniversalTime() -or
    (-not $_.ExpirationDate -and $_.LastModifiedDateTime -lt $cutoff)
}

$wildcardAllows = $allowEntries | Where-Object {
    $_.Value -match '^\*\.' -or $_.Value -eq '*'
}

$issues = [System.Collections.Generic.List[string]]::new()

if (@($staleAllows).Count -gt 0) {
    $issues.Add("$(@($staleAllows).Count) allow entry(ies) are stale (not modified in 90+ days or expired) — review and remove if no longer needed")
}

if (@($wildcardAllows).Count -gt 0) {
    $issues.Add("$(@($wildcardAllows).Count) wildcard allow entry(ies) found — overly broad allows can bypass security controls")
}

$allowCount = @($allowEntries).Count
$blockCount = @($blockEntries).Count
if ($allowCount -gt 0 -and $blockCount -eq 0) {
    $issues.Add("$allowCount allow entries exist with no corresponding block entries — review whether all allows are intentional")
}
elseif ($allowCount -gt ($blockCount * 3) -and $blockCount -gt 0) {
    $issues.Add("Allow entries ($allowCount) significantly outnumber block entries ($blockCount) — ensure allows are reviewed regularly")
}

if ($issues.Count -gt 0) {
    New-METCheckResult -CheckId 'MET-EXO005' -Category EXO -Name 'Tenant Allow/Block List' `
        -Result Warning -Severity Low `
        -AffectedObject "TABL ($allowCount allows, $blockCount blocks)" `
        -Finding ($issues -join '; ') `
        -Recommendation 'Remove stale and wildcard allow entries. Allows should be temporary and time-bound. Review the allow/block ratio periodically.' `
        -ReferenceUrl 'https://aka.ms/tabl'
}
else {
    New-METCheckResult -CheckId 'MET-EXO005' -Category EXO -Name 'Tenant Allow/Block List' `
        -Result Pass -Severity Low `
        -AffectedObject "TABL ($allowCount allows, $blockCount blocks)" `
        -Finding 'Tenant Allow/Block List entries appear well-maintained' `
        -ReferenceUrl 'https://aka.ms/tabl'
}
