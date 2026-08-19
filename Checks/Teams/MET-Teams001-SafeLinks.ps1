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
        New-METCheckResult -CheckId 'MET-Teams001' -Category Teams -Name 'Safe Links for Teams' `
            -Result Warning -Severity High -AffectedObject 'All Mailboxes' `
            -Finding 'Unable to determine effective Safe Links for Teams coverage because the mailbox list could not be retrieved.' `
            -Recommendation 'Ensure the account has Exchange View-Only Recipients permission and rerun the assessment.' `
            -ReferenceUrl 'https://aka.ms/mdo-safelinks-teams' -ErrorMessage $_.ToString()
        return
    }
}

if ($allMailboxes.Count -eq 0) {
    New-METCheckResult -CheckId 'MET-Teams001' -Category Teams -Name 'Safe Links for Teams' `
        -Result NotApplicable -Severity High -AffectedObject 'Tenant (0 mailboxes)' `
        -Finding 'No assessable mailboxes were found in the tenant.' `
        -ReferenceUrl 'https://aka.ms/mdo-safelinks-teams'
    return
}

$evaluate = {
    param($Policy, $PolicyType)
    $issues = [System.Collections.Generic.List[string]]::new()
    if (-not $Policy) {
        $issues.Add('Policy settings could not be retrieved')
        return $issues.ToArray()
    }

    if (-not $Policy.EnableSafeLinksForTeams) { $issues.Add('Safe Links for Teams is disabled') }
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

New-METEffectivePolicyCoverageResult -CheckId 'MET-Teams001' -Category Teams -Name 'Safe Links for Teams' `
    -ProtectionType 'Safe Links for Teams' -Severity High -Subjects $allMailboxes -Resolution $resolution `
    -GetPolicyIssues $evaluate -RetrievalErrors $retrievalErrors -ReferenceUrl 'https://aka.ms/mdo-safelinks-teams' `
    -Recommendation 'Assign recipients to a Standard/Strict preset or a compliant custom Safe Links policy with EnableSafeLinksForTeams enabled. Fix the effective policy for each affected recipient; unused shadowed policies do not affect this result.'
