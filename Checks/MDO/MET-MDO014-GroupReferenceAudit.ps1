$allMailboxes = $null
if ($METContext -and $METContext.AllMailboxes) {
    $allMailboxes = $METContext.AllMailboxes
} else {
    try {
        $allMailboxes = @(Get-METAssessableMailboxes)
        if ($METContext) { $METContext.AllMailboxes = $allMailboxes }
    }
    catch {
        New-METCheckResult -CheckId 'MET-MDO014' -Category MDO -Name 'Group Reference Audit' `
            -Result Fail -Severity High -AffectedObject 'All Mailboxes' `
            -Finding 'Unable to retrieve mailbox list to assess group references.' `
            -Recommendation 'Ensure the account has Exchange View-Only Recipients permission.' `
            -ReferenceUrl 'https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365' -ErrorMessage $_.ToString()
        return
    }
}

if ($allMailboxes.Count -eq 0) {
    New-METCheckResult -CheckId 'MET-MDO014' -Category MDO -Name 'Group Reference Audit' `
        -Result NotApplicable -Severity Medium -AffectedObject 'All Mailboxes' `
        -Finding 'No mailboxes found in the tenant.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365'
    return
}

$groupCache = if ($METContext -and $METContext.GroupMembers) { $METContext.GroupMembers } else { @{} }
$retrievalErrors = [System.Collections.Generic.List[string]]::new()

$sources = @(
    @{ Label = 'EOP Preset';       Getter = { @(Get-EOPProtectionPolicyRule -ErrorAction Stop | Where-Object State -eq 'Enabled') } },
    @{ Label = 'MDO Preset';       Getter = { @(Get-ATPProtectionPolicyRule -ErrorAction Stop | Where-Object State -eq 'Enabled') } },
    @{ Label = 'Safe Links';       Getter = { @(Get-SafeLinksRule -ErrorAction Stop | Where-Object State -eq 'Enabled') } },
    @{ Label = 'Safe Attachments'; Getter = { @(Get-SafeAttachmentRule -ErrorAction Stop | Where-Object State -eq 'Enabled') } },
    @{ Label = 'Anti-Phishing';    Getter = { @(Get-AntiPhishRule -ErrorAction Stop | Where-Object { $_.State -eq 'Enabled' -and $_.Name -ne 'Office365 AntiPhish Default' }) } },
    @{ Label = 'Anti-Spam';        Getter = { @(Get-HostedContentFilterRule -ErrorAction Stop | Where-Object { $_.State -eq 'Enabled' -and $_.Name -ne 'Default' }) } }
)

$referencedBy = @{}

foreach ($source in $sources) {
    try { $rules = & $source.Getter }
    catch {
        $retrievalErrors.Add("Unable to retrieve $($source.Label) rules. $($_.ToString())")
        continue
    }
    foreach ($rule in $rules) {
        $groupIds = [System.Collections.Generic.List[string]]::new()
        if ($rule.SentToMemberOf) { foreach ($g in @($rule.SentToMemberOf)) { $groupIds.Add([string]$g) } }
        if ($rule.ExceptIfSentToMemberOf) { foreach ($g in @($rule.ExceptIfSentToMemberOf)) { $groupIds.Add([string]$g) } }

        foreach ($groupId in $groupIds) {
            if (-not $referencedBy.ContainsKey($groupId)) { $referencedBy[$groupId] = [System.Collections.Generic.List[string]]::new() }
            $referencedBy[$groupId].Add("$($source.Label) rule '$($rule.Name)'")
        }
    }
}

if ($retrievalErrors.Count -gt 0) {
    New-METCheckResult -CheckId 'MET-MDO014' -Category MDO -Name 'Group Reference Audit' `
        -Result Fail -Severity High -AffectedObject 'Policy Rule Data' `
        -Finding 'Unable to complete the group reference audit because one or more rule collections could not be retrieved.' `
        -Recommendation 'Verify Exchange Online permissions and retry the assessment.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365' `
        -ErrorMessage ($retrievalErrors -join "`n")
    return
}

if ($referencedBy.Count -eq 0) {
    New-METCheckResult -CheckId 'MET-MDO014' -Category MDO -Name 'Group Reference Audit' `
        -Result NotApplicable -Severity Medium -AffectedObject 'All Threat Policies' `
        -Finding 'No enabled EOP or MDO policy rule targets recipients via group membership (SentToMemberOf/ExceptIfSentToMemberOf).' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365'
    return
}

$expansionErrors = [System.Collections.Generic.List[string]]::new()

foreach ($groupId in ($referencedBy.Keys | Sort-Object)) {
    $members = @(Expand-METGroupMembership -Identity $groupId -Cache $groupCache -RetrievalErrors $expansionErrors)
    $usedBy = $referencedBy[$groupId] -join '; '

    if ($members.Count -eq 0) {
        New-METCheckResult -CheckId 'MET-MDO014' -Category MDO -Name 'Group Reference Audit' `
            -Result Fail -Severity High -AffectedObject $groupId `
            -Finding "Group '$groupId' has 0 members but is referenced by: $usedBy. The policy condition matches nobody." `
            -Recommendation "Verify '$groupId' still exists and has members, or remove the stale reference from the rule(s) listed." `
            -ReferenceUrl 'https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365'
    }
    else {
        $memberWord = if ($members.Count -eq 1) { 'member' } else { 'members' }
        New-METCheckResult -CheckId 'MET-MDO014' -Category MDO -Name 'Group Reference Audit' `
            -Result Info -Severity Informational -AffectedObject $groupId `
            -Finding "Group '$groupId' has $($members.Count) $memberWord. Referenced by: $usedBy." `
            -ReferenceUrl 'https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365'
    }
}

if ($expansionErrors.Count -gt 0) {
    New-METCheckResult -CheckId 'MET-MDO014' -Category MDO -Name 'Group Reference Audit' `
        -Result Fail -Severity Medium -AffectedObject 'Group Membership Data' `
        -Finding 'One or more referenced groups could not be expanded to a member list.' `
        -Recommendation 'Verify Exchange Online and Microsoft Graph group-read permissions and retry the assessment.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365' `
        -ErrorMessage ($expansionErrors -join "`n")
}
