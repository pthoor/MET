# ── Mailbox list (lazy-cached in context) ────────────────────────────────────
$allMailboxes = $null
if ($METContext -and $METContext.AllMailboxes) {
    $allMailboxes = $METContext.AllMailboxes
} else {
    try {
        $allMailboxes = @(
            Get-EXOMailbox -ResultSize Unlimited -PropertySets Minimum -ErrorAction Stop |
            Select-Object -ExpandProperty PrimarySmtpAddress
        )
        if ($METContext) { $METContext.AllMailboxes = $allMailboxes }
    }
    catch {
        New-METCheckResult -CheckId 'MET-MDO013' -Category MDO -Name 'Policy Precedence Conflicts' `
            -Result Fail -Severity High -AffectedObject 'All Mailboxes' `
            -Finding 'Unable to retrieve mailbox list to assess policy precedence.' `
            -Recommendation 'Ensure the account has Exchange View-Only Recipients permission.' `
            -ReferenceUrl 'https://learn.microsoft.com/en-us/defender-office-365/preset-security-policies' -ErrorMessage $_.ToString()
        return
    }
}

$total = $allMailboxes.Count
if ($total -eq 0) {
    New-METCheckResult -CheckId 'MET-MDO013' -Category MDO -Name 'Policy Precedence Conflicts' `
        -Result NotApplicable -Severity High -AffectedObject 'All Mailboxes' `
        -Finding 'No mailboxes found in the tenant.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/defender-office-365/preset-security-policies'
    return
}

$groupCache = if ($METContext -and $METContext.GroupMembers) { $METContext.GroupMembers } else { @{} }

$matrix = if ($METContext -and $METContext.CoverageMatrix) {
    $METContext.CoverageMatrix
} else {
    Resolve-METCoverageMatrix -AllMailboxes $allMailboxes -GroupCache $groupCache
}

# ── Custom rule sources — same cmdlets Resolve-METCoverageMatrix uses as its
# "Custom" tier signals for EOP (anti-spam) and ATP (Safe Links, Anti-Phish) ──
$sources = @(
    @{ Label = 'EOP (Anti-Spam)';  Getter = { @(Get-HostedContentFilterRule -ErrorAction Stop | Where-Object { $_.State -eq 'Enabled' -and $_.Name -ne 'Default' }) };                          TierKey = 'EopTier' },
    @{ Label = 'Safe Links';       Getter = { @(Get-SafeLinksRule -ErrorAction Stop | Where-Object { $_.State -eq 'Enabled' }) };                                                                  TierKey = 'AtpTier' },
    @{ Label = 'Anti-Phish';       Getter = { @(Get-AntiPhishRule -ErrorAction Stop | Where-Object { $_.State -eq 'Enabled' -and $_.Name -ne 'Office365 AntiPhish Default' }) };                  TierKey = 'AtpTier' }
)

$shadowFindings = [System.Collections.Generic.List[string]]::new()

foreach ($source in $sources) {
    try {
        $rules = & $source.Getter
    }
    catch {
        Write-Verbose "Precedence scan for '$($source.Label)' rules failed: $_"
        continue
    }
    if (-not $rules -or $rules.Count -eq 0) { continue }

    foreach ($rule in $rules) {
        $targeted = @(Expand-METRuleRecipients -Rule $rule -AllMailboxes $allMailboxes -GroupCache $groupCache)
        if ($targeted.Count -eq 0) { continue }

        $shadowed = @($targeted | Where-Object { $matrix[$_].($source.TierKey) -in @('Standard', 'Strict') })
        if ($shadowed.Count -eq 0) { continue }

        $sample = if ($shadowed.Count -le 5) { $shadowed -join ', ' } else { "$($shadowed[0..4] -join ', ') (+$($shadowed.Count - 5) more)" }
        $scope  = Get-METRuleScope -Rule $rule
        $shadowFindings.Add("$($source.Label) rule '$($rule.Name)' ($scope) targets $($targeted.Count) mailbox(es), but $($shadowed.Count) of them are already covered by a Standard/Strict preset policy, which takes precedence — this custom rule's settings do not apply to: $sample")
    }
}

$checker = 'https://microsoft.github.io/CSS-Exchange/M365/MDO/MDOThreatPolicyChecker/'

if ($shadowFindings.Count -gt 0) {
    New-METCheckResult -CheckId 'MET-MDO013' -Category MDO -Name 'Policy Precedence Conflicts' `
        -Result Warning -Severity High -AffectedObject "$($shadowFindings.Count) custom rule(s) with precedence conflicts" `
        -Finding ($shadowFindings -join "`n`n") `
        -Recommendation "For each rule listed, decide whether the overlap is intentional. If the custom rule is meant to apply stricter or different settings than the preset for these mailboxes, move them out of the preset's scope, or raise the preset tier so it matches what the custom rule intends. If the custom rule is now redundant because a preset already covers these mailboxes at an equal or higher tier, remove or narrow the custom rule to avoid confusion. To confirm the effective policy for specific users, use MDOThreatPolicyChecker: $checker" `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/defender-office-365/preset-security-policies'
} else {
    New-METCheckResult -CheckId 'MET-MDO013' -Category MDO -Name 'Policy Precedence Conflicts' `
        -Result Pass -Severity High -AffectedObject "Tenant ($total mailboxes)" `
        -Finding "No custom EOP or MDO policies are silently shadowed by a preset policy — every custom rule's targeted recipients are either uncovered by a preset or the custom rule is the winning policy." `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/defender-office-365/preset-security-policies'
}
