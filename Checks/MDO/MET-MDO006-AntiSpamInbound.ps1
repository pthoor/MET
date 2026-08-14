$allMailboxes = $null
try {
    $allMailboxes = if ($METContext -and $METContext.AllMailboxes) { @($METContext.AllMailboxes) } else { @(Get-METAssessableMailboxes) }
    if ($METContext -and -not $METContext.AllMailboxes) { $METContext.AllMailboxes = $allMailboxes }
}
catch {
    New-METCheckResult -CheckId 'MET-MDO006' -Category MDO -Name 'Anti-Spam Inbound Effective Coverage' -Result Warning -Severity Medium -AffectedObject 'All Mailboxes' -Finding 'Unable to determine effective inbound anti-spam coverage because the mailbox list could not be retrieved.' -Recommendation 'Ensure the account has Exchange View-Only Recipients permission and rerun the assessment.' -ReferenceUrl 'https://aka.ms/mdo-antispam' -ErrorMessage $_.ToString()
    return
}
if ($allMailboxes.Count -eq 0) {
    New-METCheckResult -CheckId 'MET-MDO006' -Category MDO -Name 'Anti-Spam Inbound Effective Coverage' -Result NotApplicable -Severity Medium -AffectedObject 'Tenant (0 mailboxes)' -Finding 'No assessable mailboxes were found in the tenant.' -ReferenceUrl 'https://aka.ms/mdo-antispam'
    return
}
$errors = [System.Collections.Generic.List[string]]::new()
try { $rules = @(Get-HostedContentFilterRule -ErrorAction Stop) } catch { $rules=@(); $errors.Add("Unable to retrieve inbound anti-spam rules. $($_.ToString())") }
try { $policies = @(Get-HostedContentFilterPolicy -ErrorAction Stop) } catch { $policies=@(); $errors.Add("Unable to retrieve inbound anti-spam policies. $($_.ToString())") }
try { $presets = @(Get-ATPProtectionPolicyRule -ErrorAction Stop) } catch { $presets=@(); $errors.Add("Unable to retrieve preset policy rules. $($_.ToString())") }
$groupCache = if ($METContext -and $METContext.GroupMembers) { $METContext.GroupMembers } else { @{} }
$resolution = Resolve-METEffectivePolicy -Subjects $allMailboxes -GroupCache $groupCache -Rules $rules -Policies $policies -PresetRules $presets -IncludePresets -PolicyLinkProperty HostedContentFilterPolicy -ProtectionType 'inbound anti-spam' -RetrievalErrors $errors
$evaluate = {
    param($policy, $policyType)
    $issues = [System.Collections.Generic.List[string]]::new()
    if (-not $policy) { $issues.Add('Policy settings could not be retrieved'); return $issues.ToArray() }
    if ($policy.SpamAction -notin @('MoveToJmf','Quarantine')) { $issues.Add("Spam action is '$($policy.SpamAction)' - recommended MoveToJmf or Quarantine") }
    if ($policy.HighConfidenceSpamAction -ne 'Quarantine') { $issues.Add("High-confidence spam action is '$($policy.HighConfidenceSpamAction)' - recommended Quarantine") }
    if ($policy.PhishSpamAction -ne 'Quarantine') { $issues.Add("Phish action is '$($policy.PhishSpamAction)' - recommended Quarantine") }
    if ($policy.HighConfidencePhishAction -ne 'Quarantine') { $issues.Add("High-confidence phish action is '$($policy.HighConfidencePhishAction)' - recommended Quarantine") }
    if ($policy.BulkThreshold -gt 6) { $issues.Add("Bulk complaint level threshold is $($policy.BulkThreshold) - Standard recommends 6 or lower") }
    if ($policy.HighConfidencePhishQuarantineTag -and $policy.HighConfidencePhishQuarantineTag -ne 'AdminOnlyAccessPolicy') { $issues.Add("High-confidence phish quarantine policy is '$($policy.HighConfidencePhishQuarantineTag)' - differs from the recommended AdminOnlyAccessPolicy; users still cannot self-release high-confidence phishing") }
    if (@($policy.AllowedSenders).Count) { $issues.Add("Allowed senders contains $(@($policy.AllowedSenders).Count) entry or entries") }
    if (@($policy.AllowedSenderDomains).Count) { $issues.Add("Allowed sender domains contains $(@($policy.AllowedSenderDomains).Count) entry or entries") }
    $issues.ToArray()
}
New-METEffectivePolicyCoverageResult -CheckId 'MET-MDO006' -Name 'Anti-Spam Inbound Effective Coverage' -ProtectionType 'Inbound Anti-Spam' -Severity Medium -Subjects $allMailboxes -Resolution $resolution -GetPolicyIssues $evaluate -RetrievalErrors $errors -ReferenceUrl 'https://aka.ms/mdo-antispam' -Recommendation 'Apply a Standard/Strict preset or compliant custom inbound anti-spam policy to every affected recipient. Quarantine high-confidence spam and phishing, use BCL 6 or lower, and remove unsafe sender or domain allow entries.'
