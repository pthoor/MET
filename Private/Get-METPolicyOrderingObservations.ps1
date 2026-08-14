function Get-METPolicyOrderingObservations {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $PolicySummaries)

    $observations = [System.Collections.Generic.List[object]]::new()
    foreach ($summary in @($PolicySummaries)) {
        foreach ($blocker in @($summary.ShadowedBy | Where-Object { $_ })) {
            $severity = if ($blocker -match '^CustomCatchAll:') { 'Warning' } else { 'Info' }
            $blockedCount = [int]$summary.ShadowedRecipients
            $extent = if ($summary.EffectiveRecipients -eq 0) { 'fully' } else { 'partly' }
            $blockerLabel = $blocker -replace '^CustomCatchAll:', 'custom catch-all policy' -replace '^Custom:', 'custom policy' -replace '^Preset:', 'preset policy'
            $message = "Policy '$($summary.PolicyName)' is $extent shadowed for $blockedCount matching subject(s) by higher-precedence $blockerLabel."
            if ($severity -eq 'Warning') { $message += ' Move the catch-all below specialized custom policies if this policy is intended to apply.' }
            else { $message += ' This is informational unless the overlap is unintended.' }
            $observations.Add([PSCustomObject]@{ Severity=$severity; PolicyName=[string]$summary.PolicyName; Priority=$summary.Priority; Message=$message })
        }
        if ($summary.PolicyType -eq 'Unassociated') {
            $observations.Add([PSCustomObject]@{ Severity='Info'; PolicyName=[string]$summary.PolicyName; Priority=$null; Message="Policy '$($summary.PolicyName)' has no associated rule and currently applies to no subjects." })
        }
    }
    @($observations)
}

function Get-METPolicyCoverageRecommendations {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object] $Resolution,
        [Parameter(Mandatory)] [hashtable] $IssuesByPolicy
    )

    $fallbackAffected = @($Resolution.RecipientAssignments | Where-Object {
        $_.PolicyType -in @('Default','BuiltIn') -and @($IssuesByPolicy[$_.PolicyName]).Count -gt 0
    })
    if ($fallbackAffected.Count -eq 0) { return @() }

    $customPolicies = @($Resolution.PolicySummaries | Where-Object { $_.PolicyType -eq 'Custom' -and $_.State -eq 'Enabled' })
    if ($customPolicies.Count -gt 0) {
        return @("$($fallbackAffected.Count) subject(s) fall through to a fallback policy below baseline. If custom policies are the intended model, add a compliant catch-all with no user, group, or domain conditions after all specialized custom policies. Alternatively, expand Standard or Strict preset coverage.")
    }
    return @("$($fallbackAffected.Count) subject(s) rely on a fallback policy below baseline. Expand Standard or Strict preset coverage, or add a compliant custom catch-all as the lowest-precedence custom policy.")
}
