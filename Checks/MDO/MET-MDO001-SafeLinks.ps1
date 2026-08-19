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
        New-METCheckResult -CheckId 'MET-MDO001' -Category MDO -Name 'Safe Links Effective Coverage' `
            -Result Warning -Severity High -AffectedObject 'All Mailboxes' `
            -Finding 'Unable to determine effective Safe Links coverage because the mailbox list could not be retrieved.' `
            -Recommendation 'Ensure the account has Exchange View-Only Recipients permission and rerun the assessment.' `
            -ReferenceUrl 'https://aka.ms/mdo-safelinks' -ErrorMessage $_.ToString()
        return
    }
}

if ($allMailboxes.Count -eq 0) {
    New-METCheckResult -CheckId 'MET-MDO001' -Category MDO -Name 'Safe Links Effective Coverage' `
        -Result NotApplicable -Severity High -AffectedObject 'Tenant (0 mailboxes)' `
        -Finding 'No assessable mailboxes were found in the tenant.' `
        -ReferenceUrl 'https://aka.ms/mdo-safelinks'
    return
}

$evaluate = {
    param($Policy, $PolicyType)
    $issues = [System.Collections.Generic.List[string]]::new()
    if (-not $Policy) {
        $issues.Add('Policy settings could not be retrieved')
        return $issues.ToArray()
    }

    if (-not $Policy.EnableSafeLinksForEmail)  { $issues.Add('Safe Links for email is disabled') }
    if (-not $Policy.EnableSafeLinksForOffice) { $issues.Add('Safe Links for Office apps is disabled') }
    if (-not $Policy.TrackClicks)              { $issues.Add('Click tracking is disabled') }
    if (-not $Policy.EnableForInternalSenders) { $issues.Add('Not applied to internal senders') }
    if (-not $Policy.ScanUrls)                 { $issues.Add('Real-time URL scanning is disabled') }
    if (-not $Policy.DeliverMessageAfterScan)  { $issues.Add('Messages delivered before URL scan completes') }
    if ($Policy.AllowClickThrough)             { $issues.Add('Users can click through to blocked URLs') }
    if ($PolicyType -ne 'BuiltIn' -and $Policy.DisableURLRewrite) {
        $issues.Add('URL rewriting is disabled')
    }
    $issues.ToArray()
}

$groupCache = if ($METContext -and $METContext.GroupMembers) { $METContext.GroupMembers } else { @{} }
$retrievalErrors = [System.Collections.Generic.List[string]]::new()

if ($METContext -and $METContext.SafeLinksResolution) {
    $resolution = $METContext.SafeLinksResolution
    $retrievalErrors.AddRange([string[]]@($METContext.SafeLinksRetrievalErrors))
}
else {
    $resolution = Resolve-METSafeLinksEffectivePolicy -AllMailboxes $allMailboxes `
        -GroupCache $groupCache -RetrievalErrors $retrievalErrors
    if ($METContext) {
        $METContext.SafeLinksResolution = $resolution
        $METContext.SafeLinksRetrievalErrors = @($retrievalErrors)
    }
}

New-METEffectivePolicyCoverageResult -CheckId 'MET-MDO001' -Name 'Safe Links Effective Coverage' `
    -ProtectionType 'Safe Links' -Severity High -Subjects $allMailboxes -Resolution $resolution `
    -GetPolicyIssues $evaluate -RetrievalErrors $retrievalErrors -ReferenceUrl 'https://aka.ms/mdo-safelinks' `
    -Recommendation 'Assign recipients to a Standard/Strict preset or a compliant custom Safe Links policy. Fix the effective policy for each affected recipient; unused shadowed policies do not affect this result.'
