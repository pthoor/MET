# Verifies that quarantine policies assigned to each verdict type enforce permissions
# appropriate to the risk level of that verdict — regardless of policy name.
# Catches tenants that built custom quarantine policies but assigned them to the wrong verdicts.

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

# High   = PermissionToRelease must be $false → Fail
# Medium = PermissionToRelease = $true → Warning
# Low    = permissive policies are acceptable; skipped
$verdictRisk = @{
    'Malware'                    = 'High'
    'Impersonated User'          = 'High'
    'Impersonated Domain'        = 'High'
    'High-Confidence Phish'      = 'High'
    'Phish'                      = 'Medium'
    'Mailbox Intelligence Phish' = 'Medium'
    'Spoof'                      = 'Medium'
    'High-Confidence Spam'       = 'Low'
    'Spam'                       = 'Low'
    'Bulk'                       = 'Low'
}

$assignments = [System.Collections.Generic.List[hashtable]]::new()
$retrievalErrors = [System.Collections.Generic.List[string]]::new()

# Anti-spam (EOP + MDO)
try {
    foreach ($p in (Get-HostedContentFilterPolicy -ErrorAction Stop)) {
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
    Write-Verbose "MET-EXO009: Get-AntiPhishPolicy unavailable — may not be MDO licensed"
}

# Safe Attachments (MDO Plan 1+) — only Block action results in quarantine
try {
    foreach ($p in (Get-SafeAttachmentPolicy -ErrorAction Stop | Where-Object { $_.Action -eq 'Block' })) {
        if ($p.QuarantineTag) {
            $null = $assignments.Add(@{ Source = $p.Name; Verdict = 'Malware'; Tag = $p.QuarantineTag })
        }
    }
}
catch {
    Write-Verbose "MET-EXO009: Get-SafeAttachmentPolicy unavailable — may not be MDO licensed"
}

if ($retrievalErrors.Count -gt 0 -and $assignments.Count -eq 0) {
    New-METCheckResult -CheckId 'MET-EXO009' -Category EXO -Name 'Quarantine Policy Verdict Alignment' `
        -Result Fail -Severity High -AffectedObject 'Filter Policies' `
        -Finding "Unable to retrieve filter policies needed for verdict alignment check: $($retrievalErrors -join '; ')" `
        -Recommendation 'Ensure the account has Security Reader or higher permissions.' `
        -ReferenceUrl 'https://aka.ms/mdo-quarantinepolicies'
    return
}

$fails    = [System.Collections.Generic.List[string]]::new()
$warnings = [System.Collections.Generic.List[string]]::new()

foreach ($a in $assignments) {
    $risk = $verdictRisk[$a.Verdict]
    if ($risk -eq 'Low') { continue }

    $qp = $policyPermissions[$a.Tag]
    if (-not $qp) {
        $null = $fails.Add("Policy '$($a.Source)': $($a.Verdict) verdict references quarantine tag '$($a.Tag)' which does not exist")
        continue
    }

    if ($qp.EndUserQuarantinePermissions.PermissionToRelease) {
        $msg = "Policy '$($a.Source)': $($a.Verdict) verdict uses '$($a.Tag)' which allows users to self-release quarantined messages"
        if ($risk -eq 'High') { $null = $fails.Add($msg) }
        else                   { $null = $warnings.Add($msg) }
    }
}

if ($fails.Count -gt 0) {
    New-METCheckResult -CheckId 'MET-EXO009' -Category EXO -Name 'Quarantine Policy Verdict Alignment' `
        -Result Fail -Severity High -AffectedObject 'Quarantine Tag Assignments' `
        -Finding ($fails -join '; ') `
        -Recommendation 'For Malware, High-Confidence Phish, and impersonation verdicts, assign a quarantine policy with PermissionToRelease disabled. Use AdminOnlyAccessPolicy or a custom policy with equivalent restrictions.' `
        -ReferenceUrl 'https://aka.ms/mdo-quarantinepolicies'
}
elseif ($warnings.Count -gt 0) {
    New-METCheckResult -CheckId 'MET-EXO009' -Category EXO -Name 'Quarantine Policy Verdict Alignment' `
        -Result Warning -Severity Medium -AffectedObject 'Quarantine Tag Assignments' `
        -Finding ($warnings -join '; ') `
        -Recommendation 'For Phish, Mailbox Intelligence, and Spoof verdicts, consider using a quarantine policy where PermissionToRelease is disabled so users cannot self-release without admin review.' `
        -ReferenceUrl 'https://aka.ms/mdo-quarantinepolicies'
}
else {
    New-METCheckResult -CheckId 'MET-EXO009' -Category EXO -Name 'Quarantine Policy Verdict Alignment' `
        -Result Pass -Severity High -AffectedObject 'Quarantine Tag Assignments' `
        -Finding 'All high and medium risk verdict types use quarantine policies that prevent user self-release' `
        -ReferenceUrl 'https://aka.ms/mdo-quarantinepolicies'
}
