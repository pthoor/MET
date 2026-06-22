try {
    $rules = Get-TransportRule -ResultSize Unlimited -ErrorAction Stop
}
catch {
    New-METCheckResult -CheckId 'MET-EXO007' -Category EXO -Name 'Transport Rule Audit' `
        -Result Fail -Severity Medium -AffectedObject 'Transport Rules' `
        -Finding 'Unable to retrieve transport rules' `
        -Recommendation 'Ensure the account has Exchange View-Only Configuration or higher permissions.' `
        -ReferenceUrl 'https://aka.ms/exo-transportrules' -ErrorMessage $_.ToString()
    return
}

if (-not $rules -or @($rules).Count -eq 0) {
    New-METCheckResult -CheckId 'MET-EXO007' -Category EXO -Name 'Transport Rule Audit' `
        -Result Info -Severity Medium -AffectedObject 'Transport Rules' `
        -Finding 'No transport rules found' `
        -ReferenceUrl 'https://aka.ms/exo-transportrules'
    return
}

$spamBypassRules  = $rules | Where-Object { $_.SetSCL -eq -1 }
$safeLinksDisable = $rules | Where-Object {
    $_.SetHeaderName -match 'X-MS-Exchange-Organization-SkipSafeLinksProcessing' -or
    ($_.HeaderContainsMessageHeader -match 'X-MS-Exchange' -and $_.DeleteHeader -match 'SafeLinks')
}
$sclOverrideRules = $rules | Where-Object { $null -ne $_.SetSCL -and $_.SetSCL -ne -1 }

$issues   = [System.Collections.Generic.List[string]]::new()
$findings = [System.Collections.Generic.List[string]]::new()

if (@($spamBypassRules).Count -gt 0) {
    $names = ($spamBypassRules | Select-Object -ExpandProperty Name) -join ', '
    $issues.Add("$(@($spamBypassRules).Count) rule(s) bypass spam filtering (SCL=-1): $names")
}

if (@($safeLinksDisable).Count -gt 0) {
    $names = ($safeLinksDisable | Select-Object -ExpandProperty Name) -join ', '
    $issues.Add("$(@($safeLinksDisable).Count) rule(s) appear to disable Safe Links processing: $names")
}

if (@($sclOverrideRules).Count -gt 0) {
    $names = ($sclOverrideRules | Select-Object -ExpandProperty Name) -join ', '
    $findings.Add("$(@($sclOverrideRules).Count) rule(s) explicitly set SCL (non-bypass): $names")
}

$totalRules = @($rules).Count

if ($issues.Count -gt 0) {
    New-METCheckResult -CheckId 'MET-EXO007' -Category EXO -Name 'Transport Rule Audit' `
        -Result Warning -Severity Medium -AffectedObject "Transport Rules ($totalRules total)" `
        -Finding ($issues -join '; ') `
        -Recommendation 'Review rules that bypass spam filtering (SCL=-1) and any that disable Safe Links. Ensure these are intentional, documented, and scoped as narrowly as possible. Remove or limit rules that apply to all senders.' `
        -ReferenceUrl 'https://aka.ms/exo-transportrules'
}
else {
    $detail = if ($findings.Count -gt 0) { " Note: $($findings -join '; ')" } else { '' }
    New-METCheckResult -CheckId 'MET-EXO007' -Category EXO -Name 'Transport Rule Audit' `
        -Result Info -Severity Medium -AffectedObject "Transport Rules ($totalRules total)" `
        -Finding "No rules bypassing spam filtering or disabling Safe Links found.$detail" `
        -ReferenceUrl 'https://aka.ms/exo-transportrules'
}
