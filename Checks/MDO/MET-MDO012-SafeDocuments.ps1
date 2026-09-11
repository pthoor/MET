[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'METCheckInfo',
    Justification = 'Check metadata. Read from the AST by Get-METCheck and never executed.')]
param()

$METCheckInfo = @{
    Name           = 'Safe Documents'
    Severity       = 'Medium'
    Description    = 'Checks EnableSafeDocs and AllowSafeDocsOpen on Get-AtpPolicyForO365.'
    RequiresModule = @('ExchangeOnlineManagement')
}

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
        -Finding 'Get-AtpPolicyForO365 returned no object, so neither Safe Documents scanning nor the click-through restriction was established for this tenant. An unconfirmed state is reported as unassessed rather than a pass, because nothing here distinguishes a tenant with Safe Documents protection in place from one without it.' `
        -Recommendation 'Ensure the account has Security Reader or higher permissions, then rerun the assessment.' `
        -ReferenceUrl 'https://aka.ms/mdo-safedocuments' -ErrorMessage 'Get-AtpPolicyForO365 returned no object.'
    return
}

$missingProps = [System.Collections.Generic.List[string]]::new()
# A property present but $null was never observed by Exchange Online either - reading
# it as $false would fabricate a Fail (EnableSafeDocs) or, worse, a Pass that tells the
# reader click-through is blocked when nothing confirmed that (AllowSafeDocsOpen).
$enableSafeDocsProperty = $atpGlobal.PSObject.Properties['EnableSafeDocs']
$allowSafeDocsOpenProperty = $atpGlobal.PSObject.Properties['AllowSafeDocsOpen']
if (-not $enableSafeDocsProperty -or $null -eq $enableSafeDocsProperty.Value) { $missingProps.Add('EnableSafeDocs') }
if (-not $allowSafeDocsOpenProperty -or $null -eq $allowSafeDocsOpenProperty.Value) { $missingProps.Add('AllowSafeDocsOpen') }

if ($missingProps.Count -gt 0) {
    $propList = $missingProps -join ' and '
    $wasWere = if ($missingProps.Count -gt 1) { 'were' } else { 'was' }
    $controlText = if ($missingProps.Count -gt 1) {
        'Safe Documents scanning and the click-through restriction were'
    }
    elseif ($missingProps -contains 'EnableSafeDocs') {
        'Safe Documents scanning was'
    }
    else {
        'the click-through restriction was'
    }
    $notAPassText = if ($missingProps.Count -gt 1) {
        'nothing here distinguishes a tenant with Safe Documents scanning and the click-through restriction both enabled from one with neither'
    }
    elseif ($missingProps -contains 'EnableSafeDocs') {
        'nothing here distinguishes a tenant that scans files before allowing edit mode from one that does not'
    }
    else {
        'nothing here distinguishes a tenant that blocks click-through on a file already flagged malicious from one that allows it'
    }
    New-METCheckResult -CheckId 'MET-MDO012' -Category MDO -Name 'Safe Documents' `
        -Result NotApplicable -Severity Medium -AffectedObject 'Global MDO Settings' `
        -Finding "$propList $wasWere not returned by the global MDO policy, so whether $controlText enabled for this tenant was not established. An unconfirmed state is reported as unassessed rather than a pass, because $notAPassText." `
        -Recommendation "Confirm the setting directly with: Get-AtpPolicyForO365 | Format-List EnableSafeDocs, AllowSafeDocsOpen. An absent property usually means an ExchangeOnlineManagement version that does not expose it - update the module and rerun the assessment. Safe Documents also requires Microsoft 365 A5 or E5 Security licensing; on a tenant without that licensing these properties may legitimately not be surfaced, which is why this is reported as unassessed rather than as a pass or a failure." `
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
