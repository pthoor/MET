$allMailboxes = $null
if ($METContext -and $METContext.AllMailboxes) {
    $allMailboxes = @($METContext.AllMailboxes)
}
else {
    try {
        $allMailboxes = @(Get-METAssessableMailboxes)
        if ($METContext) { $METContext.AllMailboxes = $allMailboxes }
    }
    catch {
        New-METCheckResult -CheckId 'MET-MDO003' -Category MDO -Name 'Anti-Phishing Effective Coverage' `
            -Result Warning -Severity High -AffectedObject 'All Mailboxes' `
            -Finding 'Unable to determine effective anti-phishing coverage because the mailbox list could not be retrieved.' `
            -Recommendation 'Ensure the account has Exchange View-Only Recipients permission and rerun the assessment.' `
            -ReferenceUrl 'https://aka.ms/mdo-antiphishing' -ErrorMessage $_.ToString()
        return
    }
}

if ($allMailboxes.Count -eq 0) {
    New-METCheckResult -CheckId 'MET-MDO003' -Category MDO -Name 'Anti-Phishing Effective Coverage' `
        -Result NotApplicable -Severity High -AffectedObject 'Tenant (0 mailboxes)' `
        -Finding 'No assessable mailboxes were found in the tenant.' `
        -ReferenceUrl 'https://aka.ms/mdo-antiphishing'
    return
}

$evaluate = {
    param($Policy, $PolicyType)
    $issues = [System.Collections.Generic.List[string]]::new()
    if (-not $Policy) {
        $issues.Add('Policy settings could not be retrieved')
        return $issues.ToArray()
    }

    if (-not $Policy.EnableMailboxIntelligence)           { $issues.Add('Mailbox intelligence is disabled') }
    if (-not $Policy.EnableMailboxIntelligenceProtection) { $issues.Add('Mailbox intelligence protection is disabled') }
    elseif (-not $Policy.MailboxIntelligenceProtectionAction -or $Policy.MailboxIntelligenceProtectionAction -eq 'NoAction') {
        $issues.Add('Mailbox intelligence protection action is NoAction')
    }
    if (-not $Policy.EnableFirstContactSafetyTips)      { $issues.Add('First-contact safety tip is disabled') }
    if (-not $Policy.EnableSimilarUsersSafetyTips)      { $issues.Add('Similar-user safety tip is disabled') }
    if (-not $Policy.EnableSimilarDomainsSafetyTips)    { $issues.Add('Similar-domain safety tip is disabled') }
    if (-not $Policy.EnableUnusualCharactersSafetyTips) { $issues.Add('Unusual-characters safety tip is disabled') }

    $hasProtectedUsers = $Policy.EnableTargetedUserProtection -and @($Policy.TargetedUsersToProtect).Count -gt 0
    if (-not $hasProtectedUsers) {
        $issues.Add('Targeted user impersonation protection has no protected users')
    }
    elseif (-not $Policy.TargetedUserProtectionAction -or $Policy.TargetedUserProtectionAction -eq 'NoAction') {
        # The action is meaningful only when targeted-user detection is enabled.
        $issues.Add('Targeted user impersonation detections receive NoAction')
    }

    if (-not $Policy.EnableOrganizationDomainsProtection) {
        $issues.Add('Owned-domain impersonation protection is disabled')
    }
    elseif (-not $Policy.TargetedDomainProtectionAction -or $Policy.TargetedDomainProtectionAction -eq 'NoAction') {
        $issues.Add('Domain impersonation detections receive NoAction')
    }

    if ($null -ne $Policy.PhishThresholdLevel -and [int]$Policy.PhishThresholdLevel -lt 3) {
        $issues.Add("Phishing email threshold is $($Policy.PhishThresholdLevel); the Standard baseline is 3")
    }
    $issues.ToArray()
}

$groupCache = if ($METContext -and $METContext.GroupMembers) { $METContext.GroupMembers } else { @{} }
$retrievalErrors = [System.Collections.Generic.List[string]]::new()
$resolution = Resolve-METAntiPhishEffectivePolicy -AllMailboxes $allMailboxes `
    -GroupCache $groupCache -RetrievalErrors $retrievalErrors

New-METEffectivePolicyCoverageResult -CheckId 'MET-MDO003' -Name 'Anti-Phishing Effective Coverage' `
    -ProtectionType 'Anti-Phishing' -Severity High -Subjects $allMailboxes -Resolution $resolution `
    -GetPolicyIssues $evaluate -RetrievalErrors $retrievalErrors -ReferenceUrl 'https://aka.ms/mdo-antiphishing' `
    -Recommendation 'Fix the effective anti-phishing policy for each affected recipient. Configure protected users, owned-domain protection, mailbox intelligence protection, safety tips, appropriate actions, and a phishing threshold of at least 3. Unused shadowed policies do not affect this result.'
