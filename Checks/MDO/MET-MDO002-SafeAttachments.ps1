$atpGlobal = $null
$atpRetrievalError = $null

try {
    $atpGlobal = Get-AtpPolicyForO365 -ErrorAction Stop
}
catch {
    $atpRetrievalError = "Could not retrieve the global Safe Attachments policy: $($_.Exception.Message)"
    Write-Verbose "Could not retrieve ATP global policy for O365: $_"
}

if ($atpRetrievalError) {
    New-METCheckResult -CheckId 'MET-MDO002' -Category MDO -Name 'Safe Attachments' `
        -Result Warning -Severity High -AffectedObject 'Global Safe Attachments Settings' `
        -Finding 'The global Safe Attachments policy could not be read, so whether Safe Attachments protects SharePoint, OneDrive and Microsoft Teams file sharing was not established for this tenant. An unconfirmed state is reported as a gap rather than a pass, because nothing here distinguishes a tenant with the setting on from one with it switched off.' `
        -Recommendation 'Ensure the account has Security Reader or higher permissions, then rerun the assessment to establish the SharePoint, OneDrive and Microsoft Teams setting. The Safe Attachments policy results in this report cover email only and do not speak for that setting.' `
        -ReferenceUrl 'https://aka.ms/mdo-safeattachments' -ErrorMessage $atpRetrievalError
}
elseif (-not $atpGlobal -or -not $atpGlobal.PSObject.Properties['EnableATPForSPOTeamsODB']) {
    New-METCheckResult -CheckId 'MET-MDO002' -Category MDO -Name 'Safe Attachments' `
        -Result NotApplicable -Severity High -AffectedObject 'Global Safe Attachments Settings' `
        -Finding 'The EnableATPForSPOTeamsODB property was not returned by the global Safe Attachments policy, so whether Safe Attachments protects SharePoint, OneDrive and Microsoft Teams file sharing was not established. An unconfirmed state is reported as unassessed rather than a pass, because nothing here distinguishes a tenant with the setting on from one with it switched off.' `
        -Recommendation 'Confirm the setting directly with: Get-AtpPolicyForO365 | Format-List EnableATPForSPOTeamsODB. An absent property usually means an ExchangeOnlineManagement version that does not expose it - update the module and rerun the assessment.' `
        -ReferenceUrl 'https://aka.ms/mdo-safeattachments' `
        -ErrorMessage 'The global Safe Attachments policy did not return an EnableATPForSPOTeamsODB value.'
}
elseif ($atpGlobal.EnableATPForSPOTeamsODB) {
    New-METCheckResult -CheckId 'MET-MDO002' -Category MDO -Name 'Safe Attachments' `
        -Result Pass -Severity High -AffectedObject 'Global Safe Attachments Settings' `
        -Finding 'Safe Attachments for SharePoint, OneDrive, and Microsoft Teams is enabled (EnableATPForSPOTeamsODB = $true)' `
        -ReferenceUrl 'https://aka.ms/mdo-safeattachments'
}
else {
    New-METCheckResult -CheckId 'MET-MDO002' -Category MDO -Name 'Safe Attachments' `
        -Result Fail -Severity High -AffectedObject 'Global Safe Attachments Settings' `
        -Finding 'Safe Attachments for SharePoint, OneDrive, and Microsoft Teams is disabled (EnableATPForSPOTeamsODB = $false)' `
        -Recommendation 'Run: Set-AtpPolicyForO365 -EnableATPForSPOTeamsODB $true. This global toggle must be on for Safe Attachments to protect Teams, SharePoint, and OneDrive file sharing.' `
        -ReferenceUrl 'https://aka.ms/mdo-safeattachments'
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

# The Built-In Protection Policy has no SafeAttachmentRule entry - it applies as a
# Microsoft-managed baseline to all users not covered by any other policy.
$builtInPolicy = $safeAttachPolicies | Where-Object { $_.Name -eq 'Built-In Protection Policy' } |
    Select-Object -First 1

if (-not $activePolicies -and -not $builtInPolicy) {
    New-METCheckResult -CheckId 'MET-MDO002' -Category MDO -Name 'Safe Attachments' `
        -Result Fail -Severity High -AffectedObject 'Safe Attachment Policies' `
        -Finding "$($safeAttachPolicies.Count) Safe Attachments $(if ($safeAttachPolicies.Count -eq 1) { 'policy exists' } else { 'policies exist' }) but none have an enabled rule - no users are protected" `
        -Recommendation 'Enable a Safe Attachments rule scoped to the desired recipients, or apply the Standard/Strict preset.' `
        -ReferenceUrl 'https://aka.ms/mdo-safeattachments'
    return
}

function Invoke-SafeAttachAssessment {
    param(
        [Parameter(Mandatory)] [object] $Policy,
        [Parameter(Mandatory)] [string] $Label
    )

    # A property that is absent, or present but $null, was never observed by Exchange
    # Online. Reading either state as $false would fabricate a verdict this check did
    # not establish - most consequentially for Action, where the unobserved case is
    # indistinguishable from 'Allow', the one value that means no protection at all.
    $enableProperty = $Policy.PSObject.Properties['Enable']
    if (-not $enableProperty -or $null -eq $enableProperty.Value) {
        New-METCheckResult -CheckId 'MET-MDO002' -Category MDO -Name 'Safe Attachments' `
            -Result Warning -Severity High -AffectedObject $Label `
            -Finding 'The Enable property was not returned for this policy, so whether Safe Attachments is enabled for these recipients was not established. An unconfirmed state is reported as unassessed rather than a pass, because nothing here distinguishes a policy that inspects attachments from one that does not.' `
            -Recommendation "Confirm the setting directly with: Get-SafeAttachmentPolicy -Identity '$($Policy.Name)' | Format-List Enable. An absent property usually means an ExchangeOnlineManagement version that does not expose it - update the module and rerun the assessment." `
            -ReferenceUrl 'https://aka.ms/mdo-safeattachments' `
            -ErrorMessage 'Get-SafeAttachmentPolicy did not return an Enable value for this policy.'
        return
    }

    $issues = [System.Collections.Generic.List[string]]::new()
    $actionValue = $null

    if (-not $enableProperty.Value) {
        $issues.Add('Safe Attachments is disabled')
    }
    else {
        $actionProperty = $Policy.PSObject.Properties['Action']
        if (-not $actionProperty -or $null -eq $actionProperty.Value) {
            New-METCheckResult -CheckId 'MET-MDO002' -Category MDO -Name 'Safe Attachments' `
                -Result Warning -Severity High -AffectedObject $Label `
                -Finding 'The Action property was not returned for this policy, so whether attachments are blocked, dynamically delivered, or allowed through was not established. An unconfirmed state is reported as unassessed rather than a pass, because nothing here distinguishes a policy that blocks or dynamically delivers malicious attachments from one that allows them through unfiltered.' `
                -Recommendation "Confirm the setting directly with: Get-SafeAttachmentPolicy -Identity '$($Policy.Name)' | Format-List Action. An absent property usually means an ExchangeOnlineManagement version that does not expose it - update the module and rerun the assessment." `
                -ReferenceUrl 'https://aka.ms/mdo-safeattachments' `
                -ErrorMessage 'Get-SafeAttachmentPolicy did not return an Action value for this policy.'
            return
        }
        $actionValue = $actionProperty.Value
        if ($actionValue -eq 'Allow') {
            $issues.Add("Action is 'Allow' - attachments are not inspected")
        }
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
            -Finding "Safe Attachments is enabled with action '$actionValue'" `
            -ReferenceUrl 'https://aka.ms/mdo-safeattachments'
    }
}

foreach ($policy in $activePolicies) {
    $rule  = $ruleByPolicy[$policy.Name]
    $label = "$($policy.Name) [$(Get-METRuleScope -Rule $rule)]"
    Invoke-SafeAttachAssessment -Policy $policy -Label $label
}

if ($builtInPolicy) {
    $label = 'Built-In Protection Policy [Microsoft baseline - covers all users not protected by other policies]'
    Invoke-SafeAttachAssessment -Policy $builtInPolicy -Label $label
}
