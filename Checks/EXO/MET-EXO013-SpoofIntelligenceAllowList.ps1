[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'METCheckInfo',
    Justification = 'Check metadata. Read from the AST by Get-METCheck and never executed.')]
param()

$METCheckInfo = @{
    Name           = 'Spoof Intelligence Allow-List'
    Severity       = 'High'
    Description    = 'Reviews standing spoof-intelligence allow entries from Get-TenantAllowBlockListSpoofItems, distinguishing Internal from External spoof type.'
    RequiresModule = @('ExchangeOnlineManagement')
}

try {
    $allowEntries = @(Get-TenantAllowBlockListSpoofItems -Action Allow -ErrorAction Stop)
}
catch {
    New-METCheckResult -CheckId 'MET-EXO013' -Category EXO -Name 'Spoof Intelligence Allow-List' `
        -Result Fail -Severity High -AffectedObject 'Spoof Intelligence Allow List' `
        -Finding 'Unable to retrieve spoof intelligence allow entries' `
        -Recommendation 'Ensure the account has Security Reader or higher permissions.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-tenantallowblocklistspoofitems' `
        -ErrorMessage $_.ToString()
    return
}

if ($allowEntries.Count -eq 0) {
    New-METCheckResult -CheckId 'MET-EXO013' -Category EXO -Name 'Spoof Intelligence Allow-List' `
        -Result Info -Severity Low -AffectedObject 'Spoof Intelligence Allow List' `
        -Finding 'No spoof intelligence allow entries found - no standing exceptions to anti-spoofing protection' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-tenantallowblocklistspoofitems'
    return
}

$count = $allowEntries.Count

$unclassified = @($allowEntries | Where-Object { -not $_.PSObject.Properties['SpoofType'] -or $null -eq $_.SpoofType })
$externalCount = @($allowEntries | Where-Object { $_.PSObject.Properties['SpoofType'] -and $_.SpoofType -eq 'External' }).Count

$samples = $allowEntries | Select-Object -First 10 | ForEach-Object {
    $spoofTypeText = if (-not $_.PSObject.Properties['SpoofType'] -or $null -eq $_.SpoofType) { 'spoof type not returned' } else { $_.SpoofType }
    "$($_.SpoofedUser) via $($_.SendingInfrastructure) ($spoofTypeText)"
}

$findingParts = [System.Collections.Generic.List[string]]::new()
if ($unclassified.Count -gt 0) {
    $findingParts.Add("$count spoof intelligence allow entry(ies) found ($externalCount External, $($unclassified.Count) of $count entries did not report a spoof type)")
}
else {
    $findingParts.Add("$count spoof intelligence allow entry(ies) found ($externalCount External)")
}
$findingParts.Add(($samples -join '; '))

if ($count -gt 10) {
    $findingParts.Add("...and $($count - 10) more")
}

$errorMessage = if ($unclassified.Count -gt 0) {
    "$($unclassified.Count) of $count entries returned by Get-TenantAllowBlockListSpoofItems did not include a SpoofType value, so the Internal/External split above is a lower bound for External."
}
else {
    $null
}

New-METCheckResult -CheckId 'MET-EXO013' -Category EXO -Name 'Spoof Intelligence Allow-List' `
    -Result Warning -Severity High -AffectedObject "Spoof Intelligence Allow List ($count entries)" `
    -Finding ($findingParts -join '; ') `
    -Recommendation 'Review each allowed spoof pair. These are often created automatically when spoof intelligence learns a legitimate sender pattern, or manually during incident response, and are meant to be periodically reviewed - not permanent. Remove entries for senders/infrastructure no longer in use. External spoof types are higher risk than Internal since they permit an outside domain to impersonate a sender address. Run: Get-TenantAllowBlockListSpoofItems -Action Allow | Remove-TenantAllowBlockListSpoofItems to clean up stale entries.' `
    -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-tenantallowblocklistspoofitems' `
    -ErrorMessage $errorMessage
