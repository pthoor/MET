function Expand-METGroupMembership {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]    $Identity,
        [Parameter(Mandatory)] [hashtable] $Cache,
        # Shared visited set passed through recursive EXO calls to prevent infinite loops
        # on circular group membership. Callers should omit this — it is initialised
        # automatically on the first call and threaded through recursion internally.
        [System.Collections.Generic.HashSet[string]] $Visited = $null
    )

    if ($Cache.ContainsKey($Identity)) { return $Cache[$Identity] }

    if ($null -eq $Visited) {
        $Visited = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase)
    }
    # Cycle guard — if this identity is already being expanded in the current call
    # stack, return empty to break the loop.
    if (-not $Visited.Add($Identity)) { return @() }

    $addresses = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $graphSucceeded = $false

    # Try Graph first — handles M365 Unified Groups, Azure AD Security Groups,
    # Distribution Lists, and nested memberships via transitive expansion.
    try {
        $escaped = $Identity -replace "'", "''"
        $mgGroup = Get-MgGroup -Filter "mail eq '$escaped'" -Top 1 -ErrorAction Stop |
            Select-Object -First 1

        if (-not $mgGroup) {
            $mgGroup = Get-MgGroup -Filter "displayName eq '$escaped'" -Top 1 -ErrorAction Stop |
                Select-Object -First 1
        }

        if ($mgGroup) {
            $members = Get-MgGroupTransitiveMember -GroupId $mgGroup.Id -All -ErrorAction Stop
            foreach ($m in $members) {
                $mail = $m.AdditionalProperties['mail']
                if ($mail) {
                    $null = $addresses.Add($mail)
                    continue
                }
                $upn = $m.AdditionalProperties['userPrincipalName']
                if ($upn -and $upn -like '*@*') { $null = $addresses.Add($upn) }
            }
            $graphSucceeded = $true
        }
    }
    catch {
        Write-Verbose "Graph group expansion failed for '$Identity': $_"
    }

    # Fallback: Exchange DL expansion with recursive nested-group handling.
    # Get-MgGroupTransitiveMember already handles nesting; this fallback covers
    # mail-enabled security groups and DLs when Graph is unavailable or the group
    # was not found via the Graph filter.  The shared $Visited set prevents cycles
    # when groups nest circularly.
    if (-not $graphSucceeded) {
        try {
            $members = Get-DistributionGroupMember -Identity $Identity -ResultSize Unlimited -ErrorAction Stop
            foreach ($m in $members) {
                $rtype = [string]$m.RecipientType
                if ($rtype -match 'Group') {
                    $nestedId = if ($m.PrimarySmtpAddress) { $m.PrimarySmtpAddress } else { $m.Identity }
                    $nested   = @(Expand-METGroupMembership -Identity $nestedId -Cache $Cache -Visited $Visited)
                    foreach ($n in $nested) { $null = $addresses.Add($n) }
                } elseif ($m.PrimarySmtpAddress) {
                    $null = $addresses.Add($m.PrimarySmtpAddress)
                }
            }
        }
        catch {
            Write-Verbose "Exchange group expansion failed for '$Identity': $_"
        }
    }

    $result = [string[]]$addresses
    $Cache[$Identity] = $result
    return $result
}
