$allMailboxes = $null
try {
    $allMailboxes = if ($METContext -and $METContext.AllMailboxes) { @($METContext.AllMailboxes) } else { @(Get-METAssessableMailboxes) }
    if ($METContext -and -not $METContext.AllMailboxes) { $METContext.AllMailboxes = $allMailboxes }
}
catch {
    New-METCheckResult -CheckId 'MET-MDO009' -Category MDO -Name 'ZAP Effective Coverage' -Result Warning -Severity High -AffectedObject 'All Mailboxes' -Finding 'Unable to determine effective ZAP coverage because the mailbox list could not be retrieved.' -Recommendation 'Ensure the account has Exchange View-Only Recipients permission and rerun the assessment.' -ReferenceUrl 'https://aka.ms/mdo-zap' -ErrorMessage $_.ToString()
    return
}
if ($allMailboxes.Count -eq 0) {
    New-METCheckResult -CheckId 'MET-MDO009' -Category MDO -Name 'ZAP Effective Coverage' -Result NotApplicable -Severity High -AffectedObject 'Tenant (0 mailboxes)' -Finding 'No assessable mailboxes were found in the tenant.' -ReferenceUrl 'https://aka.ms/mdo-zap'
    return
}
$errors = [System.Collections.Generic.List[string]]::new()
try { $rules = @(Get-HostedContentFilterRule -ErrorAction Stop) } catch { $rules=@(); $errors.Add("Unable to retrieve inbound anti-spam rules. $($_.ToString())") }
try { $policies = @(Get-HostedContentFilterPolicy -ErrorAction Stop) } catch { $policies=@(); $errors.Add("Unable to retrieve inbound anti-spam policies. $($_.ToString())") }
try { $presets = @(Get-ATPProtectionPolicyRule -ErrorAction Stop) } catch { $presets=@(); $errors.Add("Unable to retrieve preset policy rules. $($_.ToString())") }
$groupCache = if ($METContext -and $METContext.GroupMembers) { $METContext.GroupMembers } else { @{} }
$resolution = Resolve-METEffectivePolicy -Subjects $allMailboxes -GroupCache $groupCache -Rules $rules -Policies $policies -PresetRules $presets -IncludePresets -PolicyLinkProperty HostedContentFilterPolicy -ProtectionType 'ZAP' -RetrievalErrors $errors
$evaluate = {
    param($policy, $policyType)
    $issues = [System.Collections.Generic.List[string]]::new()
    if (-not $policy) { $issues.Add('Policy settings could not be retrieved'); return $issues.ToArray() }
    if (-not $policy.SpamZapEnabled) { $issues.Add('ZAP for spam is disabled') }
    if (-not $policy.PhishZapEnabled) { $issues.Add('ZAP for phishing is disabled') }
    $issues.ToArray()
}
New-METEffectivePolicyCoverageResult -CheckId 'MET-MDO009' -Name 'ZAP Effective Coverage' -ProtectionType 'ZAP' -Severity High -Subjects $allMailboxes -Resolution $resolution -GetPolicyIssues $evaluate -RetrievalErrors $errors -ReferenceUrl 'https://aka.ms/mdo-zap' -Recommendation 'Enable ZAP for spam and phishing in the effective inbound anti-spam policy for every affected recipient.'
