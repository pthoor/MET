function Expand-METGroupMembership {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]    $Identity,
        [Parameter(Mandatory)] [hashtable] $Cache,
        # Shared visited set passed through recursive EXO calls to prevent infinite loops
        # on circular group membership. Callers should omit this - it is initialised
        # automatically on the first call and threaded through recursion internally.
        [System.Collections.Generic.HashSet[string]] $Visited = $null,
        [System.Collections.Generic.List[string]] $RetrievalErrors
    )

    if ($Cache.ContainsKey($Identity)) { return $Cache[$Identity] }

    if ($null -eq $Visited) {
        $Visited = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase)
    }
    # Cycle guard - if this identity is already being expanded in the current call
    # stack, return empty to break the loop.
    if (-not $Visited.Add($Identity)) { return @() }

    $addresses = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $graphSucceeded = $false
    $graphError = $null

    # Try Graph first - handles M365 Unified Groups, Azure AD Security Groups,
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
        $graphError = $_.ToString()
        Write-Verbose "Graph group expansion failed for '$Identity': $_"
    }

    # Fallback: Exchange DL expansion with recursive nested-group handling.
    # Get-MgGroupTransitiveMember already handles nesting; this fallback covers
    # mail-enabled security groups and DLs when Graph is unavailable or the group
    # was not found via the Graph filter.  The shared $Visited set prevents cycles
    # when groups nest circularly.
    if (-not $graphSucceeded) {
        $exoError = $null
        try {
            $members = Get-DistributionGroupMember -Identity $Identity -ResultSize Unlimited -ErrorAction Stop
            foreach ($m in $members) {
                $rtype = [string]$m.RecipientType
                if ($rtype -match 'Group') {
                    $nestedId = if ($m.PrimarySmtpAddress) { $m.PrimarySmtpAddress } else { $m.Identity }
                    $nested   = @(Expand-METGroupMembership -Identity $nestedId -Cache $Cache -Visited $Visited -RetrievalErrors $RetrievalErrors)
                    foreach ($n in $nested) { $null = $addresses.Add($n) }
                } elseif ($m.PrimarySmtpAddress) {
                    $null = $addresses.Add($m.PrimarySmtpAddress)
                }
            }
        }
        catch {
            $exoError = $_.ToString()
            Write-Verbose "Exchange distribution group expansion failed for '$Identity': $_"

            # Get-DistributionGroupMember only resolves distribution groups and
            # mail-enabled security groups - Microsoft 365 Groups need the separate
            # Get-UnifiedGroupLinks cmdlet, per Microsoft's own documented example.
            try {
                $links = Get-UnifiedGroupLinks -Identity $Identity -LinkType Members -ResultSize Unlimited -ErrorAction Stop
                foreach ($link in $links) {
                    if ($link.PrimarySmtpAddress) { $null = $addresses.Add($link.PrimarySmtpAddress) }
                }
            }
            catch {
                Write-Verbose "Microsoft 365 Group expansion failed for '$Identity': $_"
                if ($null -ne $RetrievalErrors) {
                    $details = if ($graphError) { "Graph: $graphError; Exchange: $exoError; Microsoft 365 Group: $($_.ToString())" } else { "Exchange: $exoError; Microsoft 365 Group: $($_.ToString())" }
                    $RetrievalErrors.Add("Unable to expand group '$Identity'. $details")
                }
                return @()
            }
        }
    }

    $result = [string[]]$addresses
    $Cache[$Identity] = $result
    return $result
}
