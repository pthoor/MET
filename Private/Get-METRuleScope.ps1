function Get-METRuleScope {
    [CmdletBinding()]
    param(
        [Parameter()] [object] $Rule,
        [int] $MaxItems = 3
    )

    if (-not $Rule) { return 'unknown scope' }

    $parts = [System.Collections.Generic.List[string]]::new()
    $parts.Add("Priority $($Rule.Priority)")

    $hasInclude = $false

    if ($Rule.SentTo -and $Rule.SentTo.Count -gt 0) {
        $hasInclude = $true
        $parts.Add("SentTo: $(Format-ScopeList $Rule.SentTo $MaxItems)")
    }
    if ($Rule.SentToMemberOf -and $Rule.SentToMemberOf.Count -gt 0) {
        $hasInclude = $true
        $parts.Add("MemberOf: $(Format-ScopeList $Rule.SentToMemberOf $MaxItems)")
    }
    if ($Rule.RecipientDomainIs -and $Rule.RecipientDomainIs.Count -gt 0) {
        $hasInclude = $true
        $parts.Add("Domain: $(Format-ScopeList $Rule.RecipientDomainIs $MaxItems)")
    }

    if (-not $hasInclude) {
        $parts.Add('catch-all')
    }

    if ($Rule.ExceptIfSentTo -and $Rule.ExceptIfSentTo.Count -gt 0) {
        $parts.Add("ExceptSentTo: $(Format-ScopeList $Rule.ExceptIfSentTo $MaxItems)")
    }
    if ($Rule.ExceptIfSentToMemberOf -and $Rule.ExceptIfSentToMemberOf.Count -gt 0) {
        $parts.Add("ExceptMemberOf: $(Format-ScopeList $Rule.ExceptIfSentToMemberOf $MaxItems)")
    }
    if ($Rule.ExceptIfRecipientDomainIs -and $Rule.ExceptIfRecipientDomainIs.Count -gt 0) {
        $parts.Add("ExceptDomain: $(Format-ScopeList $Rule.ExceptIfRecipientDomainIs $MaxItems)")
    }

    $parts -join ' · '
}

function Format-ScopeList {
    param([object[]] $Items, [int] $Max)
    if ($Items.Count -le $Max) { return $Items -join ', ' }
    "$($Items[0..($Max-1)] -join ', ') (+$($Items.Count - $Max) more)"
}
