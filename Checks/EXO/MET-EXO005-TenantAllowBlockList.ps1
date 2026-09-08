$cutoff = (Get-Date).ToUniversalTime().AddDays(-90)

$allEntries      = [System.Collections.Generic.List[PSCustomObject]]::new()
$retrievalErrors = [System.Collections.Generic.List[string]]::new()
$failedListTypes = [System.Collections.Generic.List[string]]::new()
$readListTypes   = [System.Collections.Generic.List[string]]::new()

foreach ($listType in @('Sender','Url','FileHash')) {
    try {
        $entries = Get-TenantAllowBlockListItems -ListType $listType -ErrorAction Stop
        foreach ($e in $entries) { $allEntries.Add($e) }
        $readListTypes.Add($listType)
    }
    catch {
        $failedListTypes.Add($listType)
        $retrievalErrors.Add("Could not retrieve Tenant Allow/Block List entries for type '$listType': $($_.Exception.Message)")
        Write-Verbose "Could not retrieve TABL entries for type '$listType': $_"
    }
}

$unreadableTypes = $failedListTypes -join ', '
$readableTypes   = $readListTypes -join ', '

try {
    $advancedDeliveryEntries = @(Get-TenantAllowBlockListItems -ListType Url -ListSubType AdvancedDelivery -ErrorAction Stop)
    if ($advancedDeliveryEntries.Count -gt 0) {
        New-METCheckResult -CheckId 'MET-EXO005' -Category EXO -Name 'Tenant Allow/Block List' `
            -Result Info -Severity Informational `
            -AffectedObject "Advanced Delivery URL Allow-List ($($advancedDeliveryEntries.Count) entries)" `
            -Finding "Phishing-simulation URL allow entries: $(($advancedDeliveryEntries.Value) -join ', ')" `
            -Recommendation 'These are phishing-simulation URL allows tied to the Advanced Delivery Policy (see MET-EXO014), not ordinary Tenant Allow/Block List hygiene violations - wildcards are normal, expected syntax for this subtype. Periodically review for continued relevance.' `
            -ReferenceUrl 'https://learn.microsoft.com/en-us/defender-office-365/advanced-delivery-policy-configure'
    }
    else {
        New-METCheckResult -CheckId 'MET-EXO005' -Category EXO -Name 'Tenant Allow/Block List' `
            -Result Info -Severity Informational `
            -AffectedObject 'Advanced Delivery URL Allow-List (0 entries)' `
            -Finding 'No Advanced Delivery URL allow entries are configured' `
            -ReferenceUrl 'https://learn.microsoft.com/en-us/defender-office-365/advanced-delivery-policy-configure'
    }
}
catch {
    Write-Verbose "Could not retrieve Advanced Delivery TABL entries: $_"
    New-METCheckResult -CheckId 'MET-EXO005' -Category EXO -Name 'Tenant Allow/Block List' `
        -Result Warning -Severity Low `
        -AffectedObject 'Advanced Delivery URL Allow-List (not readable)' `
        -Finding 'The Advanced Delivery URL allow-list could not be read, so the phishing-simulation URL allow entries were not assessed - this is not evidence that none are configured.' `
        -Recommendation 'Grant the account running MET the Security Reader role (or higher) in Microsoft Defender XDR and rerun. Until this list reads successfully, treat the Advanced Delivery URL allow-list as unreviewed.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/defender-office-365/advanced-delivery-policy-configure' `
        -ErrorMessage "Could not retrieve Advanced Delivery Tenant Allow/Block List entries: $($_.Exception.Message)"
}

if ($failedListTypes.Count -eq 3) {
    New-METCheckResult -CheckId 'MET-EXO005' -Category EXO -Name 'Tenant Allow/Block List' `
        -Result Warning -Severity Low -AffectedObject 'Tenant Allow/Block List (not readable)' `
        -Finding 'The Tenant Allow/Block List could not be read for any list type (Sender, Url, FileHash), so allow-entry hygiene was not assessed - this is not evidence of an empty or well-maintained list.' `
        -Recommendation 'Grant the account running MET the Security Reader role (or higher) in Microsoft Defender XDR and rerun. Until this list reads successfully, treat the tenant allow-list as unreviewed rather than clean.' `
        -ReferenceUrl 'https://aka.ms/tabl' `
        -ErrorMessage ($retrievalErrors -join "`n")
    return
}

if ($allEntries.Count -eq 0) {
    if ($failedListTypes.Count -gt 0) {
        New-METCheckResult -CheckId 'MET-EXO005' -Category EXO -Name 'Tenant Allow/Block List' `
            -Result Warning -Severity Low -AffectedObject "Tenant Allow/Block List ($readableTypes only; $unreadableTypes not readable)" `
            -Finding "The $unreadableTypes list type(s) could not be read, so the Tenant Allow/Block List was only partially assessed; no entries were found in the list type(s) that could be read ($readableTypes)." `
            -Recommendation 'Grant the account running MET the Security Reader role (or higher) in Microsoft Defender XDR and rerun. Until every list type reads successfully, treat the unreadable list types as unreviewed rather than empty.' `
            -ReferenceUrl 'https://aka.ms/tabl' `
            -ErrorMessage ($retrievalErrors -join "`n")
        return
    }

    New-METCheckResult -CheckId 'MET-EXO005' -Category EXO -Name 'Tenant Allow/Block List' `
        -Result Info -Severity Low -AffectedObject 'Tenant Allow/Block List' `
        -Finding 'No entries found in the Tenant Allow/Block List' `
        -Recommendation 'No action required. If you expect entries to be present, verify permissions (Security Reader or higher).' `
        -ReferenceUrl 'https://aka.ms/tabl'
    return
}

$allowEntries  = $allEntries | Where-Object { $_.Action -eq 'Allow' }
$blockEntries  = $allEntries | Where-Object { $_.Action -eq 'Block' }

# An entry whose Action is absent, present-but-$null, or neither 'Allow' nor 'Block' matches
# neither filter above and would otherwise vanish from both counts - counted here so the
# summary can say the allow/block totals are incomplete rather than reporting them as final.
$unclassifiedEntries = $allEntries | Where-Object {
    $actionProperty = $_.PSObject.Properties['Action']
    -not $actionProperty -or $null -eq $actionProperty.Value -or ($actionProperty.Value -ne 'Allow' -and $actionProperty.Value -ne 'Block')
}
$unclassifiedCount = @($unclassifiedEntries).Count

$staleAllows = $allowEntries | Where-Object {
    $_.ExpirationDate -and [datetime]$_.ExpirationDate -lt (Get-Date).ToUniversalTime() -or
    (-not $_.ExpirationDate -and $_.LastModifiedDateTime -lt $cutoff)
}

$wildcardAllows = $allowEntries | Where-Object {
    $_.Value -match '^\*\.' -or $_.Value -eq '*'
}

$issues = [System.Collections.Generic.List[string]]::new()

if (@($staleAllows).Count -gt 0) {
    $issues.Add("$(@($staleAllows).Count) allow entry(ies) are stale (not modified in 90+ days or expired) - review and remove if no longer needed")
}

if (@($wildcardAllows).Count -gt 0) {
    $issues.Add("$(@($wildcardAllows).Count) wildcard allow entry(ies) found - overly broad allows can bypass security controls")
}

$allowCount = @($allowEntries).Count
$blockCount = @($blockEntries).Count

if ($failedListTypes.Count -eq 0 -and $unclassifiedCount -eq 0) {
    if ($allowCount -gt 0 -and $blockCount -eq 0) {
        $issues.Add("$allowCount allow entries exist with no corresponding block entries - review whether all allows are intentional")
    }
    elseif ($allowCount -gt ($blockCount * 3) -and $blockCount -gt 0) {
        $issues.Add("Allow entries ($allowCount) significantly outnumber block entries ($blockCount) - ensure allows are reviewed regularly")
    }
}

if ($failedListTypes.Count -gt 0 -or $unclassifiedCount -gt 0) {
    $partialFindings = [System.Collections.Generic.List[string]]::new()
    $partialErrors   = [System.Collections.Generic.List[string]]::new()

    if ($failedListTypes.Count -gt 0) {
        $partialFindings.Add("The $unreadableTypes list type(s) could not be read, so only the $readableTypes entries were assessed and the allow/block ratio was not evaluated - the counts shown are incomplete")
        $partialErrors.Add(($retrievalErrors -join "`n"))
    }

    if ($unclassifiedCount -gt 0) {
        $partialFindings.Add("$unclassifiedCount entry(ies) did not return a usable Action value (Allow or Block) and could not be classified, so the allow/block counts shown describe only part of the list and the allow/block ratio was not evaluated. An unconfirmed state is reported as unassessed rather than a pass, because nothing here distinguishes a well-maintained list from one whose unclassifiable entries are concealing a problem." )
        $partialErrors.Add("Get-TenantAllowBlockListItems returned $unclassifiedCount entry(ies) without a usable Action value (Allow or Block).")
    }

    if ($issues.Count -gt 0) {
        foreach ($issue in $issues) { $partialFindings.Add($issue) }
    }
    else {
        $partialFindings.Add('No stale or wildcard allow entries were found among the entries that could be classified')
    }

    $unclassifiedSuffix = if ($unclassifiedCount -gt 0) { ", $unclassifiedCount unclassified" } else { '' }
    $affectedObject = if ($failedListTypes.Count -gt 0) {
        "TABL ($allowCount allows, $blockCount blocks from $readableTypes; $unreadableTypes not readable$unclassifiedSuffix)"
    }
    else {
        "TABL ($allowCount allows, $blockCount blocks$unclassifiedSuffix)"
    }

    New-METCheckResult -CheckId 'MET-EXO005' -Category EXO -Name 'Tenant Allow/Block List' `
        -Result Warning -Severity Low `
        -AffectedObject $affectedObject `
        -Finding ($partialFindings -join '; ') `
        -Recommendation 'Grant the account running MET the Security Reader role (or higher) in Microsoft Defender XDR and rerun so the whole list can be assessed. Remove stale and wildcard allow entries; allows should be temporary and time-bound. Until every list type reads successfully and every entry returns a usable Action value, treat the unread or unclassified portions as unreviewed rather than empty.' `
        -ReferenceUrl 'https://aka.ms/tabl' `
        -ErrorMessage ($partialErrors -join "`n")
}
elseif ($issues.Count -gt 0) {
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
