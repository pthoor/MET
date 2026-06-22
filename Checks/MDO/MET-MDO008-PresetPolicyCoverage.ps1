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
        New-METCheckResult -CheckId 'MET-MDO008' -Category MDO -Name 'Preset Policy Coverage' `
            -Result Fail -Severity High -AffectedObject 'All Mailboxes' `
            -Finding 'Unable to retrieve mailbox list to assess coverage.' `
            -Recommendation 'Ensure the account has Exchange View-Only Recipients permission.' `
            -ReferenceUrl 'https://aka.ms/mdo-presetpolicies' -ErrorMessage $_.ToString()
        return
    }
}

$total = $allMailboxes.Count
if ($total -eq 0) {
    New-METCheckResult -CheckId 'MET-MDO008' -Category MDO -Name 'Preset Policy Coverage' `
        -Result NotApplicable -Severity High -AffectedObject 'All Mailboxes' `
        -Finding 'No mailboxes found in the tenant.' `
        -ReferenceUrl 'https://aka.ms/mdo-presetpolicies'
    return
}

$groupCache = if ($METContext -and $METContext.GroupMembers) { $METContext.GroupMembers } else { @{} }

# ── Build per-mailbox EOP + ATP coverage matrix ───────────────────────────────
$matrix = Resolve-METCoverageMatrix -AllMailboxes $allMailboxes -GroupCache $groupCache

# Cache the matrix for use by Get-METReport (HTML user-coverage table)
if ($METContext) { $METContext.CoverageMatrix = $matrix }

# ── Analyse gaps ──────────────────────────────────────────────────────────────
$eopRank = @{ Default = 0; Custom = 1; Standard = 2; Strict = 3 }
$atpRank = @{ BuiltIn = 0; Custom = 1; Standard = 2; Strict = 3 }

$eopGap  = @($allMailboxes | Where-Object { $matrix[$_].EopTier -eq 'Default' })
$atpGap  = @($allMailboxes | Where-Object { $matrix[$_].AtpTier -eq 'BuiltIn' })
$mismatch = @($allMailboxes | Where-Object {
    $m = $matrix[$_]
    $m.EopTier -ne 'Default' -and $m.AtpTier -ne 'BuiltIn' -and
    $eopRank[$m.EopTier] -gt $atpRank[$m.AtpTier]
})

# ── Coverage distribution counts ─────────────────────────────────────────────
$eopDist = @{ Strict = 0; Standard = 0; Custom = 0; Default = 0 }
$atpDist = @{ Strict = 0; Standard = 0; Custom = 0; BuiltIn = 0 }
foreach ($mbx in $allMailboxes) {
    $eopDist[$matrix[$mbx].EopTier]++
    $atpDist[$matrix[$mbx].AtpTier]++
}

function Format-Pct { param([int]$n, [int]$of)
    if ($of -eq 0) { return '0%' }
    "$([int][math]::Round($n / $of * 100))%"
}

function Format-TierSummary {
    param([hashtable]$Dist, [int]$Total, [string[]]$Keys)
    ($Keys | Where-Object { $Dist[$_] -gt 0 } |
        ForEach-Object { "$_`: $($Dist[$_]) ($(Format-Pct $Dist[$_] $Total))" }) -join ' | '
}

function Format-Sample {
    param([string[]]$Lines, [int]$Max = 5)
    if ($Lines.Count -le $Max) { return $Lines -join "`n    " }
    "$($Lines[0..($Max-1)] -join "`n    ")`n    … (+$($Lines.Count - $Max) more)"
}

$checker = 'https://microsoft.github.io/CSS-Exchange/M365/MDO/MDOThreatPolicyChecker/'
$drillDown = "To confirm the effective policy for specific users, use MDOThreatPolicyChecker: $checker"

# ── EOP gap: Default-policy-only mailboxes ────────────────────────────────────
if ($eopGap.Count -gt 0) {
    $pct   = Format-Pct $eopGap.Count $total
    $level = if ($eopGap.Count -gt [int]($total * 0.10)) { 'Fail' } else { 'Warning' }

    $sampleLines = @($eopGap | ForEach-Object {
        $m = $matrix[$_]
        "$_`: ATP=$($m.AtpTier) via '$($m.AtpPolicy)'"
    })

    New-METCheckResult -CheckId 'MET-MDO008' -Category MDO `
        -Name 'Preset Policy Coverage — EOP Gap' `
        -Result $level -Severity High `
        -AffectedObject "$($eopGap.Count) of $total mailboxes" `
        -Finding "$($eopGap.Count) mailbox(es) ($pct) are covered only by the EOP Default policy — no Standard/Strict preset or custom anti-spam/anti-malware rule matches them.`n    $(Format-Sample $sampleLines)" `
        -Recommendation "1. Open https://security.microsoft.com > Email & collaboration > Policies & rules > Preset security policies.`n2. Edit the Standard or Strict preset and add these mailboxes (or their groups/domains) to the EOP included recipients list.`n3. Ensure the EOP and MDO preset rules share the same conditions so protection is consistent across both stacks.`n4. $drillDown" `
        -ReferenceUrl 'https://aka.ms/mdo-presetpolicies'
}

# ── ATP gap: Built-in-only mailboxes ─────────────────────────────────────────
if ($atpGap.Count -gt 0) {
    $pct   = Format-Pct $atpGap.Count $total
    $level = if ($atpGap.Count -gt [int]($total * 0.10)) { 'Fail' } else { 'Warning' }

    $sampleLines = @($atpGap | ForEach-Object {
        $m = $matrix[$_]
        "$_`: EOP=$($m.EopTier) via '$($m.EopPolicy)'"
    })

    New-METCheckResult -CheckId 'MET-MDO008' -Category MDO `
        -Name 'Preset Policy Coverage — MDO Gap' `
        -Result $level -Severity High `
        -AffectedObject "$($atpGap.Count) of $total mailboxes" `
        -Finding "$($atpGap.Count) mailbox(es) ($pct) have no explicit Safe Links, Safe Attachments, or Anti-Phish policy — they receive only the MDO Built-in Protection baseline.`n    $(Format-Sample $sampleLines)" `
        -Recommendation "1. Open https://security.microsoft.com > Email & collaboration > Policies & rules > Preset security policies.`n2. Edit the Standard or Strict MDO preset rule and ensure these mailboxes are included.`n3. Verify the MDO preset conditions match the EOP preset conditions — they are configured separately and can diverge.`n4. $drillDown" `
        -ReferenceUrl 'https://aka.ms/mdo-presetpolicies'
}

# ── EOP/ATP mismatch: preset conditions diverged ─────────────────────────────
if ($mismatch.Count -gt 0) {
    $sampleLines = @($mismatch | ForEach-Object {
        $m = $matrix[$_]
        "$_`: EOP=$($m.EopTier) via '$($m.EopPolicy)' / ATP=$($m.AtpTier) via '$($m.AtpPolicy)'"
    })

    New-METCheckResult -CheckId 'MET-MDO008' -Category MDO `
        -Name 'Preset Policy Coverage — EOP/MDO Mismatch' `
        -Result Warning -Severity Medium `
        -AffectedObject "$($mismatch.Count) of $total mailboxes" `
        -Finding "$($mismatch.Count) mailbox(es) have a higher EOP protection tier than their MDO protection tier — the EOP and MDO preset policy conditions have diverged.`n    $(Format-Sample $sampleLines)" `
        -Recommendation "1. Open https://security.microsoft.com > Email & collaboration > Policies & rules > Preset security policies.`n2. Compare the 'Apply to' conditions of the EOP rule and MDO rule for the same tier.`n3. Align the SentTo, MemberOf, and RecipientDomainIs conditions so both rules cover the same recipients.`n4. $drillDown" `
        -ReferenceUrl 'https://aka.ms/mdo-presetpolicies'
}

# ── Contradiction detection ───────────────────────────────────────────────────
# Checks all active policy rules for users who appear in both include and exception
# conditions.  Exception conditions always win in Exchange Online, so such users
# silently fall through to a lower-priority policy even though they seem covered.

$contradictionSets = @(
    @{ Label = 'EOP Preset';       Getter = { @(Get-EOPProtectionPolicyRule -ErrorAction Stop | Where-Object State -eq 'Enabled') } },
    @{ Label = 'MDO Preset';       Getter = { @(Get-ATPProtectionPolicyRule -ErrorAction Stop | Where-Object State -eq 'Enabled') } },
    @{ Label = 'Safe Links';       Getter = { @(Get-SafeLinksRule -ErrorAction Stop | Where-Object State -eq 'Enabled') } },
    @{ Label = 'Safe Attachments'; Getter = { @(Get-SafeAttachmentRule -ErrorAction Stop | Where-Object State -eq 'Enabled') } },
    @{ Label = 'Anti-Phishing';    Getter = { @(Get-AntiPhishRule -ErrorAction Stop | Where-Object { $_.State -eq 'Enabled' -and $_.Name -ne 'Office365 AntiPhish Default' }) } },
    @{ Label = 'Anti-Spam';        Getter = { @(Get-HostedContentFilterRule -ErrorAction Stop | Where-Object { $_.State -eq 'Enabled' -and $_.Name -ne 'Default' }) } }
)

$allContradictions = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($set in $contradictionSets) {
    try {
        $rules = & $set.Getter
        if (-not $rules -or $rules.Count -eq 0) { continue }
        $found = @(Find-METRuleContradictions -Rules $rules -AllMailboxes $allMailboxes -GroupCache $groupCache -PolicyType $set.Label)
        foreach ($c in $found) { $allContradictions.Add($c) }
    }
    catch {
        Write-Verbose "Contradiction scan for '$($set.Label)' rules failed: $_"
    }
}

if ($allContradictions.Count -gt 0) {
    $byRule = $allContradictions | Group-Object RuleName
    $findingLines = $byRule | ForEach-Object {
        $entries  = @($_.Group)
        $ptype    = $entries[0].PolicyType
        $priority = $entries[0].Priority
        $addrLines = $entries | ForEach-Object {
            "$($_.Address)`: included via $($_.IncludeReason); exception via $($_.ExcludeReason)"
        }
        "$ptype rule '$($_.Name)' (Priority $priority) - $($entries.Count) user(s) included but overridden by an exception:`n$($addrLines -join "`n")"
    }

    New-METCheckResult -CheckId 'MET-MDO008' -Category MDO `
        -Name 'Preset Policy Coverage — Condition Contradictions' `
        -Result Warning -Severity Medium `
        -AffectedObject "$($byRule.Count) rule(s) with include/exception conflicts" `
        -Finding ($findingLines -join "`n`n") `
        -Recommendation "For each rule listed, verify whether the exception was intentional. If a user must be excluded from a policy, confirm they are explicitly covered by a higher-priority policy so they do not fall to a weaker default.`n$drillDown" `
        -ReferenceUrl 'https://aka.ms/mdo-presetpolicies'
}

# ── No gaps, no mismatch, no contradictions: single Pass result ───────────────
if ($eopGap.Count -eq 0 -and $atpGap.Count -eq 0 -and $mismatch.Count -eq 0 -and $allContradictions.Count -eq 0) {
    $eopSummary = Format-TierSummary -Dist $eopDist -Total $total -Keys Strict, Standard, Custom, Default
    $atpSummary = Format-TierSummary -Dist $atpDist -Total $total -Keys Strict, Standard, Custom, BuiltIn
    New-METCheckResult -CheckId 'MET-MDO008' -Category MDO -Name 'Preset Policy Coverage' `
        -Result Pass -Severity High -AffectedObject "Tenant ($total mailboxes)" `
        -Finding "All $total mailboxes have consistent EOP and MDO policy coverage with no condition contradictions detected.`nEOP: $eopSummary`nMDO: $atpSummary" `
        -ReferenceUrl 'https://aka.ms/mdo-presetpolicies'
}
