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

function Get-SafeLinksPolicyIssues {
    param([object] $Policy, [string] $PolicyType)

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
    return $issues.ToArray()
}

function Format-SafeLinksRecipientSample {
    param([string[]] $Recipients, [int] $Maximum = 10)
    $sorted = @($Recipients | Sort-Object)
    if ($sorted.Count -le $Maximum) { return ($sorted -join ', ') }
    return "$($sorted[0..($Maximum - 1)] -join ', ') (+$($sorted.Count - $Maximum) more)"
}

$groupCache = if ($METContext -and $METContext.GroupMembers) { $METContext.GroupMembers } else { @{} }
$retrievalErrors = [System.Collections.Generic.List[string]]::new()
$resolution = Resolve-METSafeLinksEffectivePolicy -AllMailboxes $allMailboxes `
    -GroupCache $groupCache -RetrievalErrors $retrievalErrors

$policyMetadata = [System.Collections.Generic.List[hashtable]]::new()
$policyLines = [System.Collections.Generic.List[string]]::new()
$issuesByPolicy = @{}

foreach ($summary in @($resolution.PolicySummaries)) {
    $issues = @(Get-SafeLinksPolicyIssues -Policy $summary.Policy -PolicyType $summary.PolicyType)
    $issuesByPolicy[$summary.PolicyName] = $issues
    $configuration = if ($issues.Count -eq 0) { 'Pass' } else { 'Below baseline' }
    $impact = if ($summary.EffectiveRecipients -gt 0) {
        "Affects $($summary.EffectiveRecipients) recipient(s)"
    }
    elseif ($summary.State -eq 'Enabled') {
        'None - shadowed for all current recipients'
    }
    else {
        'None - rule is disabled or policy is unassociated'
    }

    $issueText = if ($issues.Count -gt 0) { " | Issues: $($issues -join '; ')" } else { '' }
    $policyLines.Add("$($summary.PolicyName) | Type: $($summary.PolicyType) | Scope: $($summary.ScopeDescription) | Effective recipients: $($summary.EffectiveRecipients) of $($allMailboxes.Count) | Configuration: $configuration | Impact: $impact$issueText")
    $policyObservations = @(Get-METPolicyOrderingObservations -PolicySummaries @($summary))
    $policyMetadata.Add(@{
        PolicyName              = [string]$summary.PolicyName
        PolicyType              = [string]$summary.PolicyType
        Tier                    = [string]$summary.Tier
        Priority                = $summary.Priority
        State                   = [string]$summary.State
        Scope                   = [string]$summary.ScopeDescription
        EffectiveRecipientCount = [int]$summary.EffectiveRecipients
        ConfigurationStatus     = $configuration
        CurrentImpact           = $impact
        Issues                  = $issues
        OrderingObservations    = @($policyObservations | ForEach-Object Message)
    })
}

$affectedRecipients = [System.Collections.Generic.List[string]]::new()
foreach ($assignment in @($resolution.RecipientAssignments)) {
    $issues = @($issuesByPolicy[$assignment.PolicyName])
    if ($issues.Count -gt 0) { $affectedRecipients.Add([string]$assignment.Recipient) }
}

$coverageComplete = ($retrievalErrors.Count -eq 0)
$orderingObservations = @(Get-METPolicyOrderingObservations -PolicySummaries @($resolution.PolicySummaries))
$orderingWarnings = @($orderingObservations | Where-Object Severity -eq 'Warning')
$coverageRecommendations = @(Get-METPolicyCoverageRecommendations -Resolution $resolution -IssuesByPolicy $issuesByPolicy)
$compliantCount = $allMailboxes.Count - $affectedRecipients.Count
$result = if (-not $coverageComplete) { 'Warning' } elseif ($affectedRecipients.Count -gt 0) { 'Fail' } elseif ($orderingWarnings.Count) { 'Warning' } else { 'Pass' }

$headline = if (-not $coverageComplete) {
    "Safe Links effective coverage is incomplete for $($allMailboxes.Count) mailbox(es)."
}
elseif ($affectedRecipients.Count -gt 0) {
    "$compliantCount of $($allMailboxes.Count) mailbox(es) meet the Safe Links baseline; $($affectedRecipients.Count) receive an effective policy below baseline."
}
else {
    "All $($allMailboxes.Count) mailbox(es) receive an effective Safe Links policy that meets the baseline."
}

$findingParts = [System.Collections.Generic.List[string]]::new()
$findingParts.Add($headline)
if ($affectedRecipients.Count -gt 0) {
    $findingParts.Add("Affected recipients: $(Format-SafeLinksRecipientSample -Recipients $affectedRecipients.ToArray())")
}
$findingParts.Add("Policy coverage:`n$($policyLines -join "`n")")
if ($orderingObservations.Count) { $findingParts.Add("Policy ordering observations:`n$(@($orderingObservations | ForEach-Object Message) -join "`n")") }
if ($coverageRecommendations.Count) { $findingParts.Add("Coverage recommendations:`n$($coverageRecommendations -join "`n")") }

$metadata = @{
    DetailType           = 'EffectivePolicyCoverage'
    ProtectionType       = 'Safe Links'
    TotalRecipients      = $allMailboxes.Count
    CompliantRecipients  = $compliantCount
    EffectiveRecipients  = $resolution.RecipientAssignments.Count
    AffectedRecipients   = @($affectedRecipients)
    CoverageComplete     = $coverageComplete
    RetrievalErrors      = @($retrievalErrors)
    Policies             = @($policyMetadata)
    OrderingObservations = @($orderingObservations)
    CoverageRecommendations = @($coverageRecommendations)
}

New-METCheckResult -CheckId 'MET-MDO001' -Category MDO -Name 'Safe Links Effective Coverage' `
    -Result $result -Severity High -AffectedObject "Tenant ($($allMailboxes.Count) mailboxes)" `
    -Finding ($findingParts -join "`n") `
    -Recommendation 'Assign recipients to a Standard/Strict preset or a compliant custom Safe Links policy. Fix the effective policy for each affected recipient; unused shadowed policies do not affect this result.' `
    -ReferenceUrl 'https://aka.ms/mdo-safelinks' `
    -ErrorMessage $(if ($retrievalErrors.Count -gt 0) { $retrievalErrors -join "`n" } else { $null }) `
    -Metadata $metadata
