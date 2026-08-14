function New-METEffectivePolicyCoverageResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $CheckId,
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string] $ProtectionType,
        [Parameter(Mandatory)] [ValidateSet('High','Medium','Low','Informational')] [string] $Severity,
        [Parameter(Mandatory)] [string[]] $Subjects,
        [Parameter(Mandatory)] [object] $Resolution,
        [Parameter(Mandatory)] [scriptblock] $GetPolicyIssues,
        [scriptblock] $GetPolicyWarnings,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [System.Collections.Generic.List[string]] $RetrievalErrors,
        [Parameter(Mandatory)] [string] $ReferenceUrl,
        [Parameter(Mandatory)] [string] $Recommendation,
        [string] $SubjectLabel = 'mailboxes'
    )

    $policyMetadata = [System.Collections.Generic.List[hashtable]]::new()
    $policyLines = [System.Collections.Generic.List[string]]::new()
    $issuesByPolicy = @{}
    $warningsByPolicy = @{}
    foreach ($summary in @($Resolution.PolicySummaries)) {
        $issues = @(& $GetPolicyIssues $summary.Policy $summary.PolicyType)
        $warnings = if ($GetPolicyWarnings) { @(& $GetPolicyWarnings $summary.Policy $summary.PolicyType) } else { @() }
        $issuesByPolicy[$summary.PolicyName] = $issues
        $warningsByPolicy[$summary.PolicyName] = $warnings
        $configuration = if ($issues.Count) { 'Below baseline' } elseif ($warnings.Count) { 'Review recommended' } else { 'Pass' }
        $impact = if ($summary.EffectiveRecipients -gt 0) { "Affects $($summary.EffectiveRecipients) subject(s)" } elseif ($summary.State -eq 'Enabled') { 'None - shadowed for all current subjects' } else { 'None - rule is disabled or policy is unassociated' }
        $allObservations = @($issues) + @($warnings)
        $issueText = if ($allObservations.Count) { " | Issues: $($allObservations -join '; ')" } else { '' }
        $policyLines.Add("$($summary.PolicyName) | Type: $($summary.PolicyType) | Scope: $($summary.ScopeDescription) | Effective subjects: $($summary.EffectiveRecipients) of $($Subjects.Count) | Configuration: $configuration | Impact: $impact$issueText")
        $policyObservations = @(Get-METPolicyOrderingObservations -PolicySummaries @($summary))
        $policyMetadata.Add(@{ PolicyName=[string]$summary.PolicyName; PolicyType=[string]$summary.PolicyType; Tier=[string]$summary.Tier; Priority=$summary.Priority; State=[string]$summary.State; Scope=[string]$summary.ScopeDescription; MatchedRecipientCount=[int]$summary.MatchedRecipients; EffectiveRecipientCount=[int]$summary.EffectiveRecipients; ShadowedRecipientCount=[int]$summary.ShadowedRecipients; ConfigurationStatus=$configuration; CurrentImpact=$impact; Issues=$issues; Warnings=$warnings; OrderingObservations=@($policyObservations | ForEach-Object Message) })
    }

    $affected = [System.Collections.Generic.List[string]]::new()
    $review = [System.Collections.Generic.List[string]]::new()
    foreach ($assignment in @($Resolution.RecipientAssignments)) { if (@($issuesByPolicy[$assignment.PolicyName]).Count) { $affected.Add([string]$assignment.Recipient) } }
    foreach ($assignment in @($Resolution.RecipientAssignments)) { if (@($warningsByPolicy[$assignment.PolicyName]).Count) { $review.Add([string]$assignment.Recipient) } }
    $complete = $RetrievalErrors.Count -eq 0
    $orderingObservations = @(Get-METPolicyOrderingObservations -PolicySummaries @($Resolution.PolicySummaries))
    $coverageRecommendations = @(Get-METPolicyCoverageRecommendations -Resolution $Resolution -IssuesByPolicy $issuesByPolicy)
    $orderingWarnings = @($orderingObservations | Where-Object Severity -eq 'Warning')
    $compliant = $Subjects.Count - $affected.Count
    $result = if (-not $complete) { 'Warning' } elseif ($affected.Count) { 'Fail' } elseif ($review.Count -or $orderingWarnings.Count) { 'Warning' } else { 'Pass' }
    $headline = if (-not $complete) { "$ProtectionType effective coverage is incomplete for $($Subjects.Count) $SubjectLabel." } elseif ($affected.Count) { "$compliant of $($Subjects.Count) $SubjectLabel meet the $ProtectionType baseline; $($affected.Count) receive an effective policy below baseline." } elseif ($review.Count) { "All $($Subjects.Count) $SubjectLabel have effective $ProtectionType coverage, but $($review.Count) require configuration review." } else { "All $($Subjects.Count) $SubjectLabel receive an effective $ProtectionType policy that meets the baseline." }
    $finding = [System.Collections.Generic.List[string]]::new()
    $finding.Add($headline)
    if ($affected.Count) {
        $sample = @($affected | Sort-Object | Select-Object -First 10)
        $suffix = if ($affected.Count -gt 10) { " (+$($affected.Count - 10) more)" } else { '' }
        $finding.Add("Affected subjects: $($sample -join ', ')$suffix")
    }
    $finding.Add("Policy coverage:`n$($policyLines -join "`n")")
    if ($orderingObservations.Count) { $finding.Add("Policy ordering observations:`n$(@($orderingObservations | ForEach-Object Message) -join "`n")") }
    if ($coverageRecommendations.Count) { $finding.Add("Coverage recommendations:`n$($coverageRecommendations -join "`n")") }
    $metadata = @{ DetailType='EffectivePolicyCoverage'; ProtectionType=$ProtectionType; TotalRecipients=$Subjects.Count; CompliantRecipients=$compliant; EffectiveRecipients=@($Resolution.RecipientAssignments).Count; AffectedRecipients=@($affected); ReviewRecipients=@($review); CoverageComplete=$complete; RetrievalErrors=@($RetrievalErrors); OrderingObservations=@($orderingObservations); CoverageRecommendations=@($coverageRecommendations); Policies=@($policyMetadata) }

    New-METCheckResult -CheckId $CheckId -Category MDO -Name $Name -Result $result -Severity $Severity `
        -AffectedObject "Tenant ($($Subjects.Count) $SubjectLabel)" -Finding ($finding -join "`n") `
        -Recommendation $Recommendation -ReferenceUrl $ReferenceUrl `
        -ErrorMessage $(if ($RetrievalErrors.Count) { $RetrievalErrors -join "`n" } else { $null }) -Metadata $metadata
}
