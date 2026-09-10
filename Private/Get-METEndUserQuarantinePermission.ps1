function Get-METEndUserQuarantinePermission {
    <#
    .SYNOPSIS
        Reads the end-user permission bits off a Get-QuarantinePolicy object.

    .DESCRIPTION
        Get-QuarantinePolicy returns EndUserQuarantinePermissions as a formatted
        System.String - "[PermissionToBlockSender: True <newline> PermissionToRelease: False ...]" -
        not a typed object, and it does not return EndUserQuarantinePermissionsValue at all
        (that name is a New-/Set-QuarantinePolicy input parameter only). Reading
        $policy.EndUserQuarantinePermissions.PermissionToRelease therefore always yields
        $null regardless of the real configuration.

        This helper parses that string (and tolerates a typed object, in case a future
        module version changes the shape) into a PSCustomObject with one Boolean per
        permission. It returns $null when the property is absent, empty, or no permission
        token could be read - callers treat that as "not established", per the absent-property
        convention in CLAUDE.md.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter()]
        $QuarantinePolicy
    )

    if (-not $QuarantinePolicy) { return $null }

    $property = $QuarantinePolicy.PSObject.Properties['EndUserQuarantinePermissions']
    if (-not $property -or $null -eq $property.Value) { return $null }
    $raw = $property.Value

    $permissionNames = @(
        'PermissionToViewHeader'
        'PermissionToDownload'
        'PermissionToAllowSender'
        'PermissionToBlockSender'
        'PermissionToRequestRelease'
        'PermissionToRelease'
        'PermissionToPreview'
        'PermissionToDelete'
    )

    $parsed = [ordered]@{}
    $anyObserved = $false

    if ($raw -is [string]) {
        foreach ($name in $permissionNames) {
            $match = [regex]::Match($raw, "$name\s*:\s*(True|False)", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            if ($match.Success) {
                $parsed[$name] = [bool]::Parse($match.Groups[1].Value)
                $anyObserved = $true
            }
            else {
                $parsed[$name] = $null
            }
        }
    }
    else {
        foreach ($name in $permissionNames) {
            $member = $raw.PSObject.Properties[$name]
            if ($member -and $null -ne $member.Value) {
                $parsed[$name] = [bool]$member.Value
                $anyObserved = $true
            }
            else {
                $parsed[$name] = $null
            }
        }
    }

    if (-not $anyObserved) { return $null }

    [PSCustomObject]$parsed
}
