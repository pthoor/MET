function Expand-METRuleRecipients {
    # Resolves which mailboxes in $AllMailboxes are covered by a single policy rule,
    # respecting SentTo / SentToMemberOf / RecipientDomainIs include conditions and
    # their ExceptIf counterparts. When no include conditions are present the rule is
    # treated as a catch-all and covers all mailboxes before exceptions are applied.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]    $Rule,
        [Parameter(Mandatory)] [string[]]  $AllMailboxes,
        [Parameter(Mandatory)] [hashtable] $GroupCache
    )

    $covered = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)

    # ── Include conditions ────────────────────────────────────────────────────
    $hasInclude = $false

    if ($Rule.SentTo) {
        $hasInclude = $true
        foreach ($addr in @($Rule.SentTo)) { $null = $covered.Add($addr) }
    }

    if ($Rule.SentToMemberOf) {
        $hasInclude = $true
        foreach ($grp in @($Rule.SentToMemberOf)) {
            $members = @(Expand-METGroupMembership -Identity $grp -Cache $GroupCache)
            foreach ($m in $members) { $null = $covered.Add($m) }
        }
    }

    if ($Rule.RecipientDomainIs) {
        $hasInclude = $true
        foreach ($mbx in $AllMailboxes) {
            $domain = ($mbx -split '@', 2)[1]
            if ($Rule.RecipientDomainIs -contains $domain) { $null = $covered.Add($mbx) }
        }
    }

    # No include conditions = catch-all rule; covers every mailbox before exceptions are applied
    if (-not $hasInclude) {
        foreach ($mbx in $AllMailboxes) { $null = $covered.Add($mbx) }
    }

    if ($covered.Count -eq 0) { return @() }

    # Intersect with actual mailboxes — rules may reference addresses outside the tenant
    $mailboxSet = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]$AllMailboxes, [System.StringComparer]::OrdinalIgnoreCase)
    $null = $covered.IntersectWith($mailboxSet)

    # ── Exception conditions ──────────────────────────────────────────────────
    if ($Rule.ExceptIfSentTo) {
        foreach ($addr in @($Rule.ExceptIfSentTo)) { $null = $covered.Remove($addr) }
    }

    if ($Rule.ExceptIfSentToMemberOf) {
        foreach ($grp in @($Rule.ExceptIfSentToMemberOf)) {
            $members = @(Expand-METGroupMembership -Identity $grp -Cache $GroupCache)
            foreach ($m in $members) { $null = $covered.Remove($m) }
        }
    }

    if ($Rule.ExceptIfRecipientDomainIs) {
        $toRemove = @($covered | Where-Object {
            $domain = ($_ -split '@', 2)[1]
            $Rule.ExceptIfRecipientDomainIs -contains $domain
        })
        foreach ($addr in $toRemove) { $null = $covered.Remove($addr) }
    }

    return [string[]]$covered
}
