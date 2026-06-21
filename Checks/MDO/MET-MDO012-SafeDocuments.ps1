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

$issues = [System.Collections.Generic.List[string]]::new()

if (-not $atpGlobal.EnableSafeDocs) {
    $issues.Add('Safe Documents is disabled — Office files opened in Protected View are not scanned before allowing edit mode')
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
