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

if ($METContext -and $METContext.GroupMembers) {
    $groupCache = $METContext.GroupMembers
}
else {
    $groupCache = @{}
    if ($METContext) { $METContext.GroupMembers = $groupCache }
}
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
# Errors already surfaced against a specific group, so the trailing summary
# does not report the same failure a second time.
$reportedErrors = [System.Collections.Generic.List[string]]::new()

foreach ($groupId in ($referencedBy.Keys | Sort-Object)) {
    $errorsBefore = $expansionErrors.Count
    $members = @(Expand-METGroupMembership -Identity $groupId -Cache $groupCache -RetrievalErrors $expansionErrors)
    $usedBy = $referencedBy[$groupId] -join '; '
    $newErrors = @(if ($expansionErrors.Count -gt $errorsBefore) { $expansionErrors[$errorsBefore..($expansionErrors.Count - 1)] })

    # An empty member list means "no members" only when resolution actually
    # succeeded - Expand-METGroupMembership returns @() for a failed lookup too,
    # appending the reason to $expansionErrors. A group that still yielded
    # members despite an error only lost a nested group, so it is reported as
    # Info here and the shortfall is summarised at the end.
    if ($members.Count -eq 0 -and $newErrors.Count -gt 0) {
        foreach ($e in $newErrors) { $reportedErrors.Add($e) }
        New-METCheckResult -CheckId 'MET-MDO014' -Category MDO -Name 'Group Reference Audit' `
            -Result Fail -Severity Medium -AffectedObject $groupId `
            -Finding "Group '$groupId' referenced by $usedBy could not be resolved to a member list, so its policy coverage could not be assessed." `
            -Recommendation "Verify Exchange Online and Microsoft Graph group-read permissions, and confirm '$groupId' still exists." `
            -ReferenceUrl 'https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365' `
            -ErrorMessage ($newErrors -join "`n")
    }
    elseif ($members.Count -eq 0) {
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

# Only errors not already attributed to a specific group above - e.g. a nested
# group that failed to expand while its parent resolved successfully.
$unreported = @($expansionErrors | Where-Object { $reportedErrors -notcontains $_ })
if ($unreported.Count -gt 0) {
    New-METCheckResult -CheckId 'MET-MDO014' -Category MDO -Name 'Group Reference Audit' `
        -Result Fail -Severity Medium -AffectedObject 'Group Membership Data' `
        -Finding 'One or more nested groups could not be expanded to a member list, so the member counts reported above may be incomplete.' `
        -Recommendation 'Verify Exchange Online and Microsoft Graph group-read permissions and retry the assessment.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365' `
        -ErrorMessage ($unreported -join "`n")
}
