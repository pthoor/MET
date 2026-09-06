try {
    $atpGlobal = Get-AtpPolicyForO365 -ErrorAction Stop
}
catch {
    New-METCheckResult -CheckId 'MET-MDO012' -Category MDO -Name 'Safe Documents' `
        -Result Fail -Severity Medium -AffectedObject 'Global MDO Settings' `
        -Finding 'Unable to retrieve global MDO policy' `
        -Recommendation 'Ensure the account has Security Reader or higher permissions.' `
        -ReferenceUrl 'https://aka.ms/mdo-safedocuments' -ErrorMessage $_.ToString()
    return
}

if (-not $atpGlobal) {
    New-METCheckResult -CheckId 'MET-MDO012' -Category MDO -Name 'Safe Documents' `
        -Result NotApplicable -Severity Medium -AffectedObject 'Global MDO Settings' `
        -Finding 'Get-AtpPolicyForO365 returned no object, so neither Safe Documents scanning nor the click-through restriction was established for this tenant.' `
        -Recommendation 'Ensure the account has Security Reader or higher permissions, then rerun the assessment.' `
        -ReferenceUrl 'https://aka.ms/mdo-safedocuments' -ErrorMessage 'Get-AtpPolicyForO365 returned no object.'
    return
}

$missingProps = [System.Collections.Generic.List[string]]::new()
if (-not $atpGlobal.PSObject.Properties['EnableSafeDocs']) { $missingProps.Add('EnableSafeDocs') }
if (-not $atpGlobal.PSObject.Properties['AllowSafeDocsOpen']) { $missingProps.Add('AllowSafeDocsOpen') }

if ($missingProps.Count -gt 0) {
    $propList = $missingProps -join ' and '
    $controlText = if ($missingProps.Count -gt 1) {
        'Safe Documents scanning and the click-through restriction were'
    }
    elseif ($missingProps -contains 'EnableSafeDocs') {
        'Safe Documents scanning was'
    }
    else {
        'the click-through restriction was'
    }
    New-METCheckResult -CheckId 'MET-MDO012' -Category MDO -Name 'Safe Documents' `
        -Result NotApplicable -Severity Medium -AffectedObject 'Global MDO Settings' `
        -Finding "$propList was not returned by the global MDO policy, so whether $controlText enabled for this tenant was not established." `
        -Recommendation 'Confirm the setting directly with: Get-AtpPolicyForO365 | Format-List EnableSafeDocs, AllowSafeDocsOpen. An absent property usually means an ExchangeOnlineManagement version that does not expose it - update the module and rerun the assessment. Safe Documents also requires Microsoft 365 A5 or E5 Security licensing; on a tenant without that licensing these properties may legitimately not be surfaced, which is why this is reported as unassessed rather than a failure.' `
        -ReferenceUrl 'https://aka.ms/mdo-safedocuments' `
        -ErrorMessage "The global MDO policy did not return: $propList."
    return
}

$issues = [System.Collections.Generic.List[string]]::new()

if (-not $atpGlobal.EnableSafeDocs) {
    $issues.Add('Safe Documents is disabled - Office files opened in Protected View are not scanned before allowing edit mode')
}

if ($atpGlobal.AllowSafeDocsOpen) {
    $issues.Add('Users are allowed to click through Protected View even when Safe Documents identifies the file as malicious')
}

if ($issues.Count -gt 0) {
    New-METCheckResult -CheckId 'MET-MDO012' -Category MDO -Name 'Safe Documents' `
        -Result Fail -Severity Medium -AffectedObject 'Global MDO Settings' `
        -Finding ($issues -join '; ') `
        -Recommendation 'Run: Set-AtpPolicyForO365 -EnableSafeDocs $true -AllowSafeDocsOpen $false. Safe Documents requires Microsoft 365 A5 or E5 Security licensing. When enabled, files opened in Protected View are scanned before users can exit Protected View.' `
        -ReferenceUrl 'https://aka.ms/mdo-safedocuments'
}
else {
    New-METCheckResult -CheckId 'MET-MDO012' -Category MDO -Name 'Safe Documents' `
        -Result Pass -Severity Medium -AffectedObject 'Global MDO Settings' `
        -Finding 'Safe Documents is enabled and click-through for malicious files is blocked' `
        -ReferenceUrl 'https://aka.ms/mdo-safedocuments'
}
