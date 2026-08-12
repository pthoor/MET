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
        -Finding 'No spoof intelligence allow entries found — no standing exceptions to anti-spoofing protection' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-tenantallowblocklistspoofitems'
    return
}

$count = $allowEntries.Count
$externalCount = @($allowEntries | Where-Object { $_.SpoofType -eq 'External' }).Count

$samples = $allowEntries | Select-Object -First 10 | ForEach-Object {
    "$($_.SpoofedUser) via $($_.SendingInfrastructure) ($($_.SpoofType))"
}

$findingParts = [System.Collections.Generic.List[string]]::new()
$findingParts.Add("$count spoof intelligence allow entry(ies) found ($externalCount External)")
$findingParts.Add(($samples -join '; '))

if ($count -gt 10) {
    $findingParts.Add("...and $($count - 10) more")
}

New-METCheckResult -CheckId 'MET-EXO013' -Category EXO -Name 'Spoof Intelligence Allow-List' `
    -Result Warning -Severity High -AffectedObject "Spoof Intelligence Allow List ($count entries)" `
    -Finding ($findingParts -join '; ') `
    -Recommendation 'Review each allowed spoof pair. These are often created automatically when spoof intelligence learns a legitimate sender pattern, or manually during incident response, and are meant to be periodically reviewed — not permanent. Remove entries for senders/infrastructure no longer in use. External spoof types are higher risk than Internal since they permit an outside domain to impersonate a sender address. Run: Get-TenantAllowBlockListSpoofItems -Action Allow | Remove-TenantAllowBlockListSpoofItems to clean up stale entries.' `
    -ReferenceUrl 'https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-tenantallowblocklistspoofitems'
