try {
    $safeLinksRules    = @(Get-SafeLinksRule    -ErrorAction Stop | Sort-Object Priority)
    $safeLinesPolicies = @(Get-SafeLinksPolicy  -ErrorAction Stop)
}
catch {
    New-METCheckResult -CheckId 'MET-MDO001' -Category MDO -Name 'Safe Links' `
        -Result Fail -Severity High -AffectedObject 'Safe Links Policies' `
        -Finding 'Unable to retrieve Safe Links policies' `
        -Recommendation 'Ensure the account has Security Reader or higher permissions.' `
        -ReferenceUrl 'https://aka.ms/mdo-safelinks' -ErrorMessage $_.ToString()
    return
}

if (-not $safeLinesPolicies) {
    New-METCheckResult -CheckId 'MET-MDO001' -Category MDO -Name 'Safe Links' `
        -Result Fail -Severity High -AffectedObject 'Safe Links Policies' `
        -Finding 'No Safe Links policies found' `
        -Recommendation 'Create and enable a Safe Links policy covering all recipients, or apply the Standard/Strict preset.' `
        -ReferenceUrl 'https://aka.ms/mdo-safelinks'
    return
}

# Build policy-name → rule lookup. Safe Links has no built-in IsDefault catch-all;
# each policy requires an enabled rule to be active.
$ruleByPolicy = @{}
foreach ($r in $safeLinksRules) { $ruleByPolicy[$r.SafeLinksPolicy] = $r }

$activePolicies = @($safeLinesPolicies | Where-Object {
    $r = $ruleByPolicy[$_.Name]
    $r -and $r.State -eq 'Enabled'
})

# The Built-In Protection Policy has no SafeLinksRule entry — it applies as a
# Microsoft-managed baseline to all users not covered by any other policy.
$builtInPolicy = $safeLinesPolicies | Where-Object { $_.Name -eq 'Built-In Protection Policy' } |
    Select-Object -First 1

if (-not $activePolicies -and -not $builtInPolicy) {
    New-METCheckResult -CheckId 'MET-MDO001' -Category MDO -Name 'Safe Links' `
        -Result Fail -Severity High -AffectedObject 'Safe Links Policies' `
        -Finding "$($safeLinesPolicies.Count) Safe Links $(if ($safeLinesPolicies.Count -eq 1) { 'policy exists' } else { 'policies exist' }) but none have an enabled rule — no users are protected" `
        -Recommendation 'Enable a Safe Links rule scoped to the desired recipients, or apply the Standard/Strict preset.' `
        -ReferenceUrl 'https://aka.ms/mdo-safelinks'
    return
}

function Invoke-SafeLinksAssessment {
    param(
        [Parameter(Mandatory)] [object]  $Policy,
        [Parameter(Mandatory)] [string]  $Label,
        [Parameter(Mandatory)] [bool]    $IsBuiltIn
    )

    $issues = [System.Collections.Generic.List[string]]::new()

    if (-not $Policy.EnableSafeLinksForEmail)  { $issues.Add('Safe Links for email is disabled') }
    if (-not $Policy.EnableSafeLinksForOffice) { $issues.Add('Safe Links for Office apps is disabled') }
    if (-not $Policy.TrackClicks)              { $issues.Add('Click tracking is disabled') }
    if (-not $Policy.EnableForInternalSenders) { $issues.Add('Not applied to internal senders') }
    if (-not $Policy.ScanUrls)                 { $issues.Add('Real-time URL scanning is disabled') }
    if (-not $Policy.DeliverMessageAfterScan)  { $issues.Add('Messages delivered before URL scan completes') }
    if ($Policy.AllowClickThrough)             { $issues.Add('Users can click through to blocked URLs') }

    # Built-In Protection intentionally disables URL rewriting — it relies on click-time
    # detonation instead. Flagging this would be a false positive for Built-In.
    if (-not $IsBuiltIn -and $Policy.DisableURLRewrite) {
        $issues.Add('URL rewriting is disabled — Standard/Strict require rewriting for email')
    }

    if ($issues.Count -gt 0) {
        New-METCheckResult -CheckId 'MET-MDO001' -Category MDO -Name 'Safe Links' `
            -Result Fail -Severity High -AffectedObject $Label `
            -Finding ($issues -join '; ') `
            -Recommendation 'Enable Safe Links for email and Office apps, enable real-time scanning and wait for scan before delivery, disable click-through, keep URL rewriting enabled, and apply to internal senders. Consider applying the Standard or Strict preset policy.' `
            -ReferenceUrl 'https://aka.ms/mdo-safelinks'
    }
    else {
        New-METCheckResult -CheckId 'MET-MDO001' -Category MDO -Name 'Safe Links' `
            -Result Pass -Severity High -AffectedObject $Label `
            -Finding 'Safe Links is correctly configured' `
            -ReferenceUrl 'https://aka.ms/mdo-safelinks'
    }
}

foreach ($policy in $activePolicies) {
    $rule  = $ruleByPolicy[$policy.Name]
    $label = "$($policy.Name) [$(Get-METRuleScope -Rule $rule)]"
    Invoke-SafeLinksAssessment -Policy $policy -Label $label -IsBuiltIn $false
}

if ($builtInPolicy) {
    $label = 'Built-In Protection Policy [Microsoft baseline — covers all users not protected by other policies]'
    Invoke-SafeLinksAssessment -Policy $builtInPolicy -Label $label -IsBuiltIn $true
}
