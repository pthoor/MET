function Find-METRuleContradictions {
    # Detects mailboxes that appear in both include and exception conditions of the
    # same policy rule.  In Exchange Online, exception conditions always win — such
    # users receive no protection from the rule even though they appear to be
    # explicitly included.
    #
    # Only flags rules that have at least one explicit include condition (SentTo,
    # SentToMemberOf, or RecipientDomainIs).  Catch-all rules with no include
    # conditions rely on exceptions for intentional scoping and are skipped.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object[]]  $Rules,
        [Parameter(Mandatory)] [string[]]  $AllMailboxes,
        [Parameter(Mandatory)] [hashtable] $GroupCache,
        [Parameter(Mandatory)] [string]    $PolicyType
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    $domainMap = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.List[string]]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($mbx in $AllMailboxes) {
        $d = ($mbx -split '@', 2)[1]
        if (-not $domainMap.ContainsKey($d)) {
            $domainMap[$d] = [System.Collections.Generic.List[string]]::new()
        }
        $domainMap[$d].Add($mbx)
    }

    foreach ($rule in $Rules) {
        if ($rule.State -ne 'Enabled') { continue }

        # ── Build include map: address → condition description ─────────────
        $includeMap = [System.Collections.Generic.Dictionary[string,string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase)

        foreach ($addr in @($rule.SentTo)) {
            if ($addr -and -not $includeMap.ContainsKey($addr)) {
                $includeMap[$addr] = "directly listed in SentTo"
            }
        }

        foreach ($grp in @($rule.SentToMemberOf)) {
            if (-not $grp) { continue }
            foreach ($m in @(Expand-METGroupMembership -Identity $grp -Cache $GroupCache)) {
                if (-not $includeMap.ContainsKey($m)) {
                    $includeMap[$m] = "member of included group '$grp'"
                }
            }
        }

        if ($rule.RecipientDomainIs) {
            foreach ($domain in @($rule.RecipientDomainIs)) {
                if ($domainMap.ContainsKey($domain)) {
                    foreach ($mbx in $domainMap[$domain]) {
                        if (-not $includeMap.ContainsKey($mbx)) {
                            $includeMap[$mbx] = "matched by included domain '$domain'"
                        }
                    }
                }
            }
        }

        # No explicit include conditions = catch-all; exceptions are intentional
        if ($includeMap.Count -eq 0) { continue }

        # ── Build exclude map: address → condition description ─────────────
        $excludeMap = [System.Collections.Generic.Dictionary[string,string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase)

        foreach ($addr in @($rule.ExceptIfSentTo)) {
            if ($addr -and -not $excludeMap.ContainsKey($addr)) {
                $excludeMap[$addr] = "directly listed in ExceptIfSentTo"
            }
        }

        foreach ($grp in @($rule.ExceptIfSentToMemberOf)) {
            if (-not $grp) { continue }
            foreach ($m in @(Expand-METGroupMembership -Identity $grp -Cache $GroupCache)) {
                if (-not $excludeMap.ContainsKey($m)) {
                    $excludeMap[$m] = "member of excluded group '$grp'"
                }
            }
        }

        if ($rule.ExceptIfRecipientDomainIs) {
            foreach ($domain in @($rule.ExceptIfRecipientDomainIs)) {
                if ($domainMap.ContainsKey($domain)) {
                    foreach ($mbx in $domainMap[$domain]) {
                        if (-not $excludeMap.ContainsKey($mbx)) {
                            $excludeMap[$mbx] = "matched by excluded domain '$domain'"
                        }
                    }
                }
            }
        }

        if ($excludeMap.Count -eq 0) { continue }

        # ── Intersection = contradictions (exception wins, user gets no cover) ─
        foreach ($addr in $includeMap.Keys) {
            if ($excludeMap.ContainsKey($addr)) {
                $results.Add([PSCustomObject]@{
                    PolicyType    = $PolicyType
                    RuleName      = $rule.Name
                    Priority      = $rule.Priority
                    Address       = $addr
                    IncludeReason = $includeMap[$addr]
                    ExcludeReason = $excludeMap[$addr]
                })
            }
        }
    }

    return $results.ToArray()
}
