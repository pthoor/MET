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

function Get-AntiPhishPolicyIssues {
    param([object] $Policy)
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
    return $issues.ToArray()
}

function Format-AntiPhishRecipientSample {
    param([string[]] $Recipients, [int] $Maximum = 10)
    $sorted = @($Recipients | Sort-Object)
    if ($sorted.Count -le $Maximum) { return ($sorted -join ', ') }
    return "$($sorted[0..($Maximum - 1)] -join ', ') (+$($sorted.Count - $Maximum) more)"
}

$groupCache = if ($METContext -and $METContext.GroupMembers) { $METContext.GroupMembers } else { @{} }
$retrievalErrors = [System.Collections.Generic.List[string]]::new()
$resolution = Resolve-METAntiPhishEffectivePolicy -AllMailboxes $allMailboxes `
    -GroupCache $groupCache -RetrievalErrors $retrievalErrors

$policyMetadata = [System.Collections.Generic.List[hashtable]]::new()
$policyLines = [System.Collections.Generic.List[string]]::new()
$issuesByPolicy = @{}
foreach ($summary in @($resolution.PolicySummaries)) {
    $issues = @(Get-AntiPhishPolicyIssues -Policy $summary.Policy)
    $issuesByPolicy[$summary.PolicyName] = $issues
    $configuration = if ($issues.Count -eq 0) { 'Pass' } else { 'Below baseline' }
    $impact = if ($summary.EffectiveRecipients -gt 0) { "Affects $($summary.EffectiveRecipients) recipient(s)" }
        elseif ($summary.State -eq 'Enabled') { 'None - shadowed for all current recipients' }
        else { 'None - rule is disabled or policy is unassociated' }
    $issueText = if ($issues.Count -gt 0) { " | Issues: $($issues -join '; ')" } else { '' }
    $policyLines.Add("$($summary.PolicyName) | Type: $($summary.PolicyType) | Scope: $($summary.ScopeDescription) | Effective recipients: $($summary.EffectiveRecipients) of $($allMailboxes.Count) | Configuration: $configuration | Impact: $impact$issueText")
    $policyObservations = @(Get-METPolicyOrderingObservations -PolicySummaries @($summary))
    $policyMetadata.Add(@{
        PolicyName = [string]$summary.PolicyName; PolicyType = [string]$summary.PolicyType
        Tier = [string]$summary.Tier; Priority = $summary.Priority; State = [string]$summary.State
        Scope = [string]$summary.ScopeDescription; EffectiveRecipientCount = [int]$summary.EffectiveRecipients
        ConfigurationStatus = $configuration; CurrentImpact = $impact; Issues = $issues
        OrderingObservations = @($policyObservations | ForEach-Object Message)
    })
}

$affectedRecipients = [System.Collections.Generic.List[string]]::new()
foreach ($assignment in @($resolution.RecipientAssignments)) {
    if (@($issuesByPolicy[$assignment.PolicyName]).Count -gt 0) {
        $affectedRecipients.Add([string]$assignment.Recipient)
    }
}

$coverageComplete = ($retrievalErrors.Count -eq 0)
$orderingObservations = @(Get-METPolicyOrderingObservations -PolicySummaries @($resolution.PolicySummaries))
$orderingWarnings = @($orderingObservations | Where-Object Severity -eq 'Warning')
$coverageRecommendations = @(Get-METPolicyCoverageRecommendations -Resolution $resolution -IssuesByPolicy $issuesByPolicy)
$compliantCount = $allMailboxes.Count - $affectedRecipients.Count
$result = if (-not $coverageComplete) { 'Warning' } elseif ($affectedRecipients.Count -gt 0) { 'Fail' } elseif ($orderingWarnings.Count) { 'Warning' } else { 'Pass' }
$headline = if (-not $coverageComplete) {
    "Anti-phishing effective coverage is incomplete for $($allMailboxes.Count) mailbox(es)."
} elseif ($affectedRecipients.Count -gt 0) {
    "$compliantCount of $($allMailboxes.Count) mailbox(es) meet the anti-phishing baseline; $($affectedRecipients.Count) receive an effective policy below baseline."
} else {
    "All $($allMailboxes.Count) mailbox(es) receive an effective anti-phishing policy that meets the baseline."
}
$findingParts = [System.Collections.Generic.List[string]]::new()
$findingParts.Add($headline)
if ($affectedRecipients.Count -gt 0) {
    $findingParts.Add("Affected recipients: $(Format-AntiPhishRecipientSample -Recipients $affectedRecipients.ToArray())")
}
$findingParts.Add("Policy coverage:`n$($policyLines -join "`n")")
if ($orderingObservations.Count) { $findingParts.Add("Policy ordering observations:`n$(@($orderingObservations | ForEach-Object Message) -join "`n")") }
if ($coverageRecommendations.Count) { $findingParts.Add("Coverage recommendations:`n$($coverageRecommendations -join "`n")") }

$metadata = @{
    DetailType = 'EffectivePolicyCoverage'; ProtectionType = 'Anti-Phishing'
    TotalRecipients = $allMailboxes.Count; CompliantRecipients = $compliantCount
    EffectiveRecipients = $resolution.RecipientAssignments.Count; AffectedRecipients = @($affectedRecipients)
    CoverageComplete = $coverageComplete; RetrievalErrors = @($retrievalErrors); Policies = @($policyMetadata)
    OrderingObservations = @($orderingObservations)
    CoverageRecommendations = @($coverageRecommendations)
}

New-METCheckResult -CheckId 'MET-MDO003' -Category MDO -Name 'Anti-Phishing Effective Coverage' `
    -Result $result -Severity High -AffectedObject "Tenant ($($allMailboxes.Count) mailboxes)" `
    -Finding ($findingParts -join "`n") `
    -Recommendation 'Fix the effective anti-phishing policy for each affected recipient. Configure protected users, owned-domain protection, mailbox intelligence protection, safety tips, appropriate actions, and a phishing threshold of at least 3. Unused shadowed policies do not affect this result.' `
    -ReferenceUrl 'https://aka.ms/mdo-antiphishing' `
    -ErrorMessage $(if ($retrievalErrors.Count -gt 0) { $retrievalErrors -join "`n" } else { $null }) `
    -Metadata $metadata
