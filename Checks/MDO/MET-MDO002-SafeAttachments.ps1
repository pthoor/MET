try {
    $atpGlobal = Get-AtpPolicyForO365 -ErrorAction Stop
    if (-not $atpGlobal.EnableATPForSPOTeamsODB) {
        New-METCheckResult -CheckId 'MET-MDO002' -Category MDO -Name 'Safe Attachments' `
            -Result Fail -Severity High -AffectedObject 'Global Safe Attachments Settings' `
            -Finding 'Safe Attachments for SharePoint, OneDrive, and Microsoft Teams is disabled (EnableATPForSPOTeamsODB = $false)' `
            -Recommendation 'Run: Set-AtpPolicyForO365 -EnableATPForSPOTeamsODB $true. This global toggle must be on for Safe Attachments to protect Teams, SharePoint, and OneDrive file sharing.' `
            -ReferenceUrl 'https://aka.ms/mdo-safeattachments'
    }
}
catch {
    Write-Verbose "Could not retrieve ATP global policy for O365: $_"
}

try {
    $safeAttachRules    = @(Get-SafeAttachmentRule    -ErrorAction Stop | Sort-Object Priority)
    $safeAttachPolicies = @(Get-SafeAttachmentPolicy  -ErrorAction Stop)
}
catch {
    New-METCheckResult -CheckId 'MET-MDO002' -Category MDO -Name 'Safe Attachments' `
        -Result Fail -Severity High -AffectedObject 'Safe Attachment Policies' `
        -Finding 'Unable to retrieve Safe Attachment policies' `
        -Recommendation 'Ensure the account has Security Reader or higher permissions.' `
        -ReferenceUrl 'https://aka.ms/mdo-safeattachments' -ErrorMessage $_.ToString()
    return
}

if (-not $safeAttachPolicies) {
    New-METCheckResult -CheckId 'MET-MDO002' -Category MDO -Name 'Safe Attachments' `
        -Result Fail -Severity High -AffectedObject 'Safe Attachment Policies' `
        -Finding 'No Safe Attachment policies found' `
        -Recommendation 'Create and enable a Safe Attachments policy with action Block or DynamicDelivery.' `
        -ReferenceUrl 'https://aka.ms/mdo-safeattachments'
    return
}

$ruleByPolicy = @{}
foreach ($r in $safeAttachRules) { $ruleByPolicy[$r.SafeAttachmentPolicy] = $r }

$activePolicies = @($safeAttachPolicies | Where-Object {
    $r = $ruleByPolicy[$_.Name]
    $r -and $r.State -eq 'Enabled'
})

# The Built-In Protection Policy has no SafeAttachmentRule entry — it applies as a
# Microsoft-managed baseline to all users not covered by any other policy.
$builtInPolicy = $safeAttachPolicies | Where-Object { $_.Name -eq 'Built-In Protection Policy' } |
    Select-Object -First 1

if (-not $activePolicies -and -not $builtInPolicy) {
    New-METCheckResult -CheckId 'MET-MDO002' -Category MDO -Name 'Safe Attachments' `
        -Result Fail -Severity High -AffectedObject 'Safe Attachment Policies' `
        -Finding "$($safeAttachPolicies.Count) Safe Attachments $(if ($safeAttachPolicies.Count -eq 1) { 'policy exists' } else { 'policies exist' }) but none have an enabled rule — no users are protected" `
        -Recommendation 'Enable a Safe Attachments rule scoped to the desired recipients, or apply the Standard/Strict preset.' `
        -ReferenceUrl 'https://aka.ms/mdo-safeattachments'
    return
}

function Invoke-SafeAttachAssessment {
    param(
        [Parameter(Mandatory)] [object] $Policy,
        [Parameter(Mandatory)] [string] $Label
    )

    $issues = [System.Collections.Generic.List[string]]::new()

    if (-not $Policy.Enable) {
        $issues.Add('Safe Attachments is disabled')
    }
    elseif ($Policy.Action -eq 'Allow') {
        $issues.Add("Action is 'Allow' — attachments are not inspected")
    }

    if ($issues.Count -gt 0) {
        New-METCheckResult -CheckId 'MET-MDO002' -Category MDO -Name 'Safe Attachments' `
            -Result Fail -Severity High -AffectedObject $Label `
            -Finding ($issues -join '; ') `
            -Recommendation "Enable Safe Attachments and set the action to 'Block' or 'DynamicDelivery'. 'Allow' provides no protection." `
            -ReferenceUrl 'https://aka.ms/mdo-safeattachments'
    }
    else {
        New-METCheckResult -CheckId 'MET-MDO002' -Category MDO -Name 'Safe Attachments' `
            -Result Pass -Severity High -AffectedObject $Label `
            -Finding "Safe Attachments is enabled with action '$($Policy.Action)'" `
            -ReferenceUrl 'https://aka.ms/mdo-safeattachments'
    }
}

foreach ($policy in $activePolicies) {
    $rule  = $ruleByPolicy[$policy.Name]
    $label = "$($policy.Name) [$(Get-METRuleScope -Rule $rule)]"
    Invoke-SafeAttachAssessment -Policy $policy -Label $label
}

if ($builtInPolicy) {
    $label = 'Built-In Protection Policy [Microsoft baseline — covers all users not protected by other policies]'
    Invoke-SafeAttachAssessment -Policy $builtInPolicy -Label $label
}
