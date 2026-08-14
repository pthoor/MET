$allSenders = $null
try {
    $allSenders = if ($METContext -and $METContext.AllMailboxes) { @($METContext.AllMailboxes) } else { @(Get-METAssessableMailboxes) }
    if ($METContext -and -not $METContext.AllMailboxes) { $METContext.AllMailboxes = $allSenders }
}
catch {
    New-METCheckResult -CheckId 'MET-MDO007' -Category MDO -Name 'Anti-Spam Outbound Effective Coverage' -Result Warning -Severity Medium -AffectedObject 'All Senders' -Finding 'Unable to determine effective outbound anti-spam coverage because the sender list could not be retrieved.' -Recommendation 'Ensure the account has Exchange View-Only Recipients permission and rerun the assessment.' -ReferenceUrl 'https://aka.ms/mdo-outboundspam' -ErrorMessage $_.ToString()
    return
}
if ($allSenders.Count -eq 0) {
    New-METCheckResult -CheckId 'MET-MDO007' -Category MDO -Name 'Anti-Spam Outbound Effective Coverage' -Result NotApplicable -Severity Medium -AffectedObject 'Tenant (0 senders)' -Finding 'No assessable senders were found in the tenant.' -ReferenceUrl 'https://aka.ms/mdo-outboundspam'
    return
}
$errors = [System.Collections.Generic.List[string]]::new()
try { $rules = @(Get-HostedOutboundSpamFilterRule -ErrorAction Stop) } catch { $rules=@(); $errors.Add("Unable to retrieve outbound anti-spam rules. $($_.ToString())") }
try { $policies = @(Get-HostedOutboundSpamFilterPolicy -ErrorAction Stop) } catch { $policies=@(); $errors.Add("Unable to retrieve outbound anti-spam policies. $($_.ToString())") }
$groupCache = if ($METContext -and $METContext.GroupMembers) { $METContext.GroupMembers } else { @{} }
$resolution = Resolve-METEffectivePolicy -Subjects $allSenders -GroupCache $groupCache -Rules $rules -Policies $policies -PolicyLinkProperty HostedOutboundSpamFilterPolicy -ProtectionType 'outbound anti-spam' -ScopeType Sender -RetrievalErrors $errors
$evaluate = {
    param($policy, $policyType)
    $issues = [System.Collections.Generic.List[string]]::new()
    if (-not $policy) { $issues.Add('Policy settings could not be retrieved'); return $issues.ToArray() }
    if ($policy.AutoForwardingMode -eq 'On') { $issues.Add('Automatic external forwarding is enabled') }
    if ($policy.ActionWhenThresholdReached -ne 'BlockUser') { $issues.Add("Sending-limit action is '$($policy.ActionWhenThresholdReached)' - Standard recommends BlockUser") }
    $issues.ToArray()
}
$warnings = {
    param($policy, $policyType)
    if ($policy -and $policy.AutoForwardingMode -notin @('Off','On')) { "Automatic forwarding is '$($policy.AutoForwardingMode)' - system-controlled rather than explicitly disabled" }
}
New-METEffectivePolicyCoverageResult -CheckId 'MET-MDO007' -Name 'Anti-Spam Outbound Effective Coverage' -ProtectionType 'Outbound Anti-Spam' -Severity Medium -Subjects $allSenders -SubjectLabel 'senders' -Resolution $resolution -GetPolicyIssues $evaluate -GetPolicyWarnings $warnings -RetrievalErrors $errors -ReferenceUrl 'https://aka.ms/mdo-outboundspam' -Recommendation 'Apply a compliant outbound anti-spam policy to every affected sender. Explicitly disable automatic external forwarding and use BlockUser when sending limits are reached. Use the restricted-user alert policy for administrator notifications.'
