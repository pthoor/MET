function Resolve-METCoverageMatrix {
    # Resolves the effective MDO/EOP protection tier and winning policy name for every
    # address in AllMailboxes.  Returns a case-insensitive hashtable keyed by
    # PrimarySmtpAddress where each value is:
    #   [PSCustomObject]@{ EopTier; EopPolicy; AtpTier; AtpPolicy }
    #
    # EopTier values (ascending protection): Default < Custom < Standard < Strict
    # AtpTier values (ascending protection): BuiltIn  < Custom < Standard < Strict
    #
    # EOP covers anti-spam and anti-malware; ATP covers Safe Links, Safe Attachments,
    # and Anti-Phish.  The two preset rule sets are resolved independently because
    # their recipient conditions can diverge.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]]  $AllMailboxes,
        [Parameter(Mandatory)] [hashtable] $GroupCache
    )

    $eopRank = @{ Default = 0; Custom = 1; Standard = 2; Strict = 3 }
    $atpRank = @{ BuiltIn = 0; Custom = 1; Standard = 2; Strict = 3 }

    $eopTier   = @{}
    $eopPolicy = @{}
    $atpTier   = @{}
    $atpPolicy = @{}

    foreach ($mbx in $AllMailboxes) {
        $eopTier[$mbx]   = 'Default'
        $eopPolicy[$mbx] = 'Default Anti-Spam Policy'
        $atpTier[$mbx]   = 'BuiltIn'
        $atpPolicy[$mbx] = 'Built-In Protection Policy'
    }

    # ── EOP presets (Strict first so it wins over Standard on overlap) ────────
    foreach ($tier in @('Strict', 'Standard')) {
        $meta = Resolve-METPresetPolicy -Tier $tier -Stack EOP
        if (-not $meta.Enabled -or -not $meta.Rule) { continue }
        try {
            $covered = @(Expand-METRuleRecipients -Rule $meta.Rule -AllMailboxes $AllMailboxes -GroupCache $GroupCache)
            foreach ($addr in $covered) {
                if ($eopTier.ContainsKey($addr) -and $eopRank[$tier] -gt $eopRank[$eopTier[$addr]]) {
                    $eopTier[$addr]   = $tier
                    $eopPolicy[$addr] = $meta.PolicyName
                }
            }
        }
        catch { Write-Verbose "EOP preset '$tier' recipient expansion failed: $_" }
    }

    # ── ATP presets (resolved independently — conditions may differ from EOP) ─
    foreach ($tier in @('Strict', 'Standard')) {
        $meta = Resolve-METPresetPolicy -Tier $tier -Stack ATP
        if (-not $meta.Enabled -or -not $meta.Rule) { continue }
        try {
            $covered = @(Expand-METRuleRecipients -Rule $meta.Rule -AllMailboxes $AllMailboxes -GroupCache $GroupCache)
            foreach ($addr in $covered) {
                if ($atpTier.ContainsKey($addr) -and $atpRank[$tier] -gt $atpRank[$atpTier[$addr]]) {
                    $atpTier[$addr]   = $tier
                    $atpPolicy[$addr] = $meta.PolicyName
                }
            }
        }
        catch { Write-Verbose "ATP preset '$tier' recipient expansion failed: $_" }
    }

    # ── Custom EOP policies — only evaluate addresses still at Default ────────
    $eopNeedsCustom = @($AllMailboxes | Where-Object { $eopTier[$_] -eq 'Default' })
    if ($eopNeedsCustom.Count -gt 0) {
        try {
            $rules = @(
                Get-HostedContentFilterRule -ErrorAction Stop |
                Where-Object { $_.State -eq 'Enabled' -and $_.Name -ne 'Default' } |
                Sort-Object Priority
            )
            foreach ($rule in $rules) {
                $covered = @(Expand-METRuleRecipients -Rule $rule -AllMailboxes $eopNeedsCustom -GroupCache $GroupCache)
                foreach ($addr in $covered) {
                    if ($eopTier.ContainsKey($addr) -and $eopTier[$addr] -eq 'Default') {
                        $eopTier[$addr]   = 'Custom'
                        $eopPolicy[$addr] = $rule.Name
                    }
                }
            }
        }
        catch { Write-Verbose "Custom EOP (anti-spam) rule expansion failed: $_" }
    }

    # ── Custom ATP policies — Safe Links as primary signal ───────────────────
    $atpNeedsCustom = @($AllMailboxes | Where-Object { $atpTier[$_] -eq 'BuiltIn' })
    if ($atpNeedsCustom.Count -gt 0) {
        try {
            $rules = @(
                Get-SafeLinksRule -ErrorAction Stop |
                Where-Object { $_.State -eq 'Enabled' } |
                Sort-Object Priority
            )
            foreach ($rule in $rules) {
                $covered = @(Expand-METRuleRecipients -Rule $rule -AllMailboxes $atpNeedsCustom -GroupCache $GroupCache)
                foreach ($addr in $covered) {
                    if ($atpTier.ContainsKey($addr) -and $atpTier[$addr] -eq 'BuiltIn') {
                        $atpTier[$addr]   = 'Custom'
                        $atpPolicy[$addr] = $rule.Name
                    }
                }
            }
        }
        catch { Write-Verbose "Custom Safe Links rule expansion failed: $_" }
    }

    # ── Anti-Phish as fallback ATP signal for addresses still at BuiltIn ─────
    $atpNeedsCustom = @($AllMailboxes | Where-Object { $atpTier[$_] -eq 'BuiltIn' })
    if ($atpNeedsCustom.Count -gt 0) {
        try {
            $rules = @(
                Get-AntiPhishRule -ErrorAction Stop |
                Where-Object { $_.State -eq 'Enabled' -and $_.Name -ne 'Office365 AntiPhish Default' } |
                Sort-Object Priority
            )
            foreach ($rule in $rules) {
                $covered = @(Expand-METRuleRecipients -Rule $rule -AllMailboxes $atpNeedsCustom -GroupCache $GroupCache)
                foreach ($addr in $covered) {
                    if ($atpTier.ContainsKey($addr) -and $atpTier[$addr] -eq 'BuiltIn') {
                        $atpTier[$addr]   = 'Custom'
                        $atpPolicy[$addr] = $rule.Name
                    }
                }
            }
        }
        catch { Write-Verbose "Custom Anti-Phish rule expansion failed: $_" }
    }

    # ── Combine into a single result hashtable ────────────────────────────────
    $matrix = @{}
    foreach ($mbx in $AllMailboxes) {
        $matrix[$mbx] = [PSCustomObject]@{
            EopTier   = $eopTier[$mbx]
            EopPolicy = $eopPolicy[$mbx]
            AtpTier   = $atpTier[$mbx]
            AtpPolicy = $atpPolicy[$mbx]
        }
    }
    return $matrix
}
