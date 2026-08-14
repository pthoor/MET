function Expand-METRuleRecipients {
    # Resolves which mailboxes in $AllMailboxes are covered by a single policy rule,
    # respecting SentTo / SentToMemberOf / RecipientDomainIs include conditions and
    # their ExceptIf counterparts. When no include conditions are present the rule is
    # treated as a catch-all and covers all mailboxes before exceptions are applied.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]    $Rule,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]] $AllMailboxes,
        [Parameter(Mandatory)] [hashtable] $GroupCache,
        [ValidateSet('Recipient','Sender')] [string] $ScopeType = 'Recipient',
        [System.Collections.Generic.List[string]] $RetrievalErrors
    )

    function New-AddressSet {
        return ,([System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase))
    }

    function Test-RecipientDomain {
        param([string] $Address, [object[]] $Domains)

        if ($Address -notmatch '@(?<Domain>[^@]+)$') { return $false }
        $recipientDomain = $Matches.Domain.TrimEnd('.')
        foreach ($configuredDomain in @($Domains)) {
            $candidate = ([string]$configuredDomain).Trim().TrimStart('@').TrimEnd('.')
            if (-not $candidate) { continue }
            if ($recipientDomain.Equals($candidate, [System.StringComparison]::OrdinalIgnoreCase) -or
                $recipientDomain.EndsWith(".$candidate", [System.StringComparison]::OrdinalIgnoreCase)) {
                return $true
            }
        }
        return $false
    }

    $covered = New-AddressSet
    $directProperty = if ($ScopeType -eq 'Sender') { 'From' } else { 'SentTo' }
    $groupProperty = if ($ScopeType -eq 'Sender') { 'FromMemberOf' } else { 'SentToMemberOf' }
    $domainProperty = if ($ScopeType -eq 'Sender') { 'SenderDomainIs' } else { 'RecipientDomainIs' }
    $exceptDirectProperty = if ($ScopeType -eq 'Sender') { 'ExceptIfFrom' } else { 'ExceptIfSentTo' }
    $exceptGroupProperty = if ($ScopeType -eq 'Sender') { 'ExceptIfFromMemberOf' } else { 'ExceptIfSentToMemberOf' }
    $exceptDomainProperty = if ($ScopeType -eq 'Sender') { 'ExceptIfSenderDomainIs' } else { 'ExceptIfRecipientDomainIs' }

    # ── Include conditions ────────────────────────────────────────────────────
    $hasInclude = $false

    if ($Rule.$directProperty) {
        $hasInclude = $true
        $conditionMatches = New-AddressSet
        foreach ($addr in @($Rule.$directProperty)) { $null = $conditionMatches.Add([string]$addr) }
        $conditionMatches.IntersectWith([string[]]$AllMailboxes)
        $covered = $conditionMatches
    }

    if ($Rule.$groupProperty) {
        $conditionMatches = New-AddressSet
        foreach ($grp in @($Rule.$groupProperty)) {
            $members = @(Expand-METGroupMembership -Identity $grp -Cache $GroupCache -RetrievalErrors $RetrievalErrors)
            foreach ($m in $members) { $null = $conditionMatches.Add([string]$m) }
        }
        $conditionMatches.IntersectWith([string[]]$AllMailboxes)
        if ($hasInclude) { $covered.IntersectWith($conditionMatches) } else { $covered = $conditionMatches }
        $hasInclude = $true
    }

    if ($Rule.$domainProperty) {
        $conditionMatches = New-AddressSet
        foreach ($mbx in $AllMailboxes) {
            if (Test-RecipientDomain -Address $mbx -Domains @($Rule.$domainProperty)) {
                $null = $conditionMatches.Add($mbx)
            }
        }
        if ($hasInclude) { $covered.IntersectWith($conditionMatches) } else { $covered = $conditionMatches }
        $hasInclude = $true
    }

    # No include conditions = catch-all rule; covers every mailbox before exceptions are applied
    if (-not $hasInclude) {
        foreach ($mbx in $AllMailboxes) { $null = $covered.Add($mbx) }
    }

    if ($covered.Count -eq 0) { return @() }

    # Intersect with actual mailboxes - rules may reference addresses outside the tenant
    $mailboxSet = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]$AllMailboxes, [System.StringComparer]::OrdinalIgnoreCase)
    $null = $covered.IntersectWith($mailboxSet)

    # ── Exception conditions ──────────────────────────────────────────────────
    if ($Rule.$exceptDirectProperty) {
        foreach ($addr in @($Rule.$exceptDirectProperty)) { $null = $covered.Remove($addr) }
    }

    if ($Rule.$exceptGroupProperty) {
        foreach ($grp in @($Rule.$exceptGroupProperty)) {
            $members = @(Expand-METGroupMembership -Identity $grp -Cache $GroupCache -RetrievalErrors $RetrievalErrors)
            foreach ($m in $members) { $null = $covered.Remove($m) }
        }
    }

    if ($Rule.$exceptDomainProperty) {
        $toRemove = @($covered | Where-Object {
            Test-RecipientDomain -Address $_ -Domains @($Rule.$exceptDomainProperty)
        })
        foreach ($addr in $toRemove) { $null = $covered.Remove($addr) }
    }

    return [string[]]$covered
}
