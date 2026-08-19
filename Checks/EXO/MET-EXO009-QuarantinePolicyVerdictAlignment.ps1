# Verifies that quarantine policies assigned to Malware and High-Confidence Phish verdicts
# prevent user self-release, the only two verdicts with a restrictive floor per Microsoft's
# own Standard/Strict preset matrix. Every
# other verdict (Phish, Mailbox Intelligence Phish, Spoof, both impersonation types, spam
# tiers, Bulk) uses a full-access quarantine policy even under Strict, so they are not
# evaluated. Assignments sourced from preset-generated policies (Standard/Strict Preset
# Security Policy*) are skipped entirely - their tags are guaranteed correct by Microsoft and
# not admin-actionable. Custom policies are still checked against the actual
# PermissionToRelease bit, not the tag's name.

$policyPermissions = @{}
try {
    Get-QuarantinePolicy -ErrorAction Stop | ForEach-Object {
        $policyPermissions[$_.Name] = $_
    }
}
catch {
    New-METCheckResult -CheckId 'MET-EXO009' -Category EXO -Name 'Quarantine Policy Verdict Alignment' `
        -Result Fail -Severity High -AffectedObject 'Quarantine Policies' `
        -Finding 'Unable to retrieve quarantine policies' `
        -Recommendation 'Ensure the account has Security Reader or higher permissions.' `
        -ReferenceUrl 'https://aka.ms/mdo-quarantinepolicies' -ErrorMessage $_.ToString()
    return
}

# Only these two verdicts have a restrictive floor (PermissionToRelease must be $false) in
# Microsoft's own Default/Standard/Strict matrix. Every other verdict has no floor to enforce.
$restrictedVerdicts = @(
    'Malware'
    'High-Confidence Phish'
)

$assignments = [System.Collections.Generic.List[hashtable]]::new()
$retrievalErrors = [System.Collections.Generic.List[string]]::new()

# Anti-spam (EOP + MDO)
try {
    foreach ($p in (Get-HostedContentFilterPolicy -ErrorAction Stop)) {
        if (Test-METIsPresetSecurityPolicyName -Name $p.Name) { continue }
        $verdictMap = [ordered]@{
            HighConfidencePhishQuarantineTag = 'High-Confidence Phish'
            PhishQuarantineTag               = 'Phish'
            HighConfidenceSpamQuarantineTag  = 'High-Confidence Spam'
            SpamQuarantineTag                = 'Spam'
            BulkQuarantineTag                = 'Bulk'
        }
        foreach ($entry in $verdictMap.GetEnumerator()) {
            $tag = $p.($entry.Key)
            if ($tag) {
                $null = $assignments.Add(@{ Source = $p.Name; Verdict = $entry.Value; Tag = $tag })
            }
        }
    }
}
catch {
    $retrievalErrors.Add("Anti-spam policies: $($_.ToString())")
}

# Anti-malware
try {
    foreach ($p in (Get-MalwareFilterPolicy -ErrorAction Stop)) {
        if (Test-METIsPresetSecurityPolicyName -Name $p.Name) { continue }
        if ($p.QuarantineTag) {
            $null = $assignments.Add(@{ Source = $p.Name; Verdict = 'Malware'; Tag = $p.QuarantineTag })
        }
    }
}
catch {
    $retrievalErrors.Add("Anti-malware policies: $($_.ToString())")
}

# Anti-phish impersonation verdicts (MDO Plan 1+)
try {
    foreach ($p in (Get-AntiPhishPolicy -ErrorAction Stop)) {
        if (Test-METIsPresetSecurityPolicyName -Name $p.Name) { continue }
        $verdictMap = [ordered]@{
            TargetedUserQuarantineTag        = 'Impersonated User'
            TargetedDomainQuarantineTag      = 'Impersonated Domain'
            MailboxIntelligenceQuarantineTag = 'Mailbox Intelligence Phish'
            SpoofQuarantineTag               = 'Spoof'
        }
        foreach ($entry in $verdictMap.GetEnumerator()) {
            $tag = $p.($entry.Key)
            if ($tag) {
                $null = $assignments.Add(@{ Source = $p.Name; Verdict = $entry.Value; Tag = $tag })
            }
        }
    }
}
catch {
    Write-Verbose "MET-EXO009: Get-AntiPhishPolicy unavailable - may not be MDO licensed"
}

# Safe Attachments (MDO Plan 1+) - only Block action results in quarantine
try {
    foreach ($p in (Get-SafeAttachmentPolicy -ErrorAction Stop | Where-Object { $_.Action -eq 'Block' })) {
        if (Test-METIsPresetSecurityPolicyName -Name $p.Name) { continue }
        if ($p.QuarantineTag) {
            $null = $assignments.Add(@{ Source = $p.Name; Verdict = 'Malware'; Tag = $p.QuarantineTag })
        }
    }
}
catch {
    Write-Verbose "MET-EXO009: Get-SafeAttachmentPolicy unavailable - may not be MDO licensed"
}

if ($retrievalErrors.Count -gt 0 -and $assignments.Count -eq 0) {
    New-METCheckResult -CheckId 'MET-EXO009' -Category EXO -Name 'Quarantine Policy Verdict Alignment' `
        -Result Fail -Severity High -AffectedObject 'Filter Policies' `
        -Finding "Unable to retrieve filter policies needed for verdict alignment check: $($retrievalErrors -join '; ')" `
        -Recommendation 'Ensure the account has Security Reader or higher permissions.' `
        -ReferenceUrl 'https://aka.ms/mdo-quarantinepolicies'
    return
}

$fails = [System.Collections.Generic.List[string]]::new()

foreach ($a in $assignments) {
    if ($a.Verdict -notin $restrictedVerdicts) { continue }

    $qp = $policyPermissions[$a.Tag]
    if (-not $qp) {
        $null = $fails.Add("Policy '$($a.Source)': $($a.Verdict) verdict references quarantine tag '$($a.Tag)' which does not exist")
        continue
    }

    if ($qp.EndUserQuarantinePermissions.PermissionToRelease) {
        $null = $fails.Add("Policy '$($a.Source)': $($a.Verdict) verdict uses '$($a.Tag)' which allows users to self-release quarantined messages")
    }
}

if ($fails.Count -gt 0) {
    New-METCheckResult -CheckId 'MET-EXO009' -Category EXO -Name 'Quarantine Policy Verdict Alignment' `
        -Result Fail -Severity High -AffectedObject 'Quarantine Tag Assignments' `
        -Finding ($fails -join '; ') `
        -Recommendation 'For Malware and High-Confidence Phish verdicts, assign a quarantine policy with PermissionToRelease disabled. Use AdminOnlyAccessPolicy or a custom policy with equivalent restrictions.' `
        -ReferenceUrl 'https://aka.ms/mdo-quarantinepolicies'
}
else {
    New-METCheckResult -CheckId 'MET-EXO009' -Category EXO -Name 'Quarantine Policy Verdict Alignment' `
        -Result Pass -Severity High -AffectedObject 'Quarantine Tag Assignments' `
        -Finding 'Malware and High-Confidence Phish verdicts use quarantine policies that prevent user self-release' `
        -ReferenceUrl 'https://aka.ms/mdo-quarantinepolicies'
}
