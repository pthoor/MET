function Resolve-METTenantGuid {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $TenantId
    )

    if ($TenantId -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
        return $TenantId
    }

    if ([string]::IsNullOrWhiteSpace($TenantId)) {
        Write-Verbose 'TenantId is empty or whitespace; not attempting tenant discovery.'
        return $null
    }

    if ($TenantId -notmatch '^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$') {
        Write-Verbose "'$TenantId' is neither a GUID nor a DNS domain name; not attempting tenant discovery."
        return $null
    }

    # Domain names (e.g. contoso.onmicrosoft.com) don't compare against the GUID that
    # Get-MgContext/Get-CsTenant return, so resolve via the tenant's own unauthenticated
    # OpenID Connect discovery document - the standard way to map a domain to its tenant
    # GUID without needing an existing Graph/Teams session (avoids a chicken-and-egg
    # problem when the very thing being checked is whether that session is trustworthy).
    try {
        $escaped = [uri]::EscapeDataString($TenantId)
        $discovery = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$escaped/v2.0/.well-known/openid-configuration" -TimeoutSec 15 -ErrorAction Stop
        if ($discovery.issuer -match '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})') {
            return $Matches[1]
        }
    }
    catch {
        Write-Verbose "Unable to resolve tenant GUID for '$TenantId': $_"
    }

    return $null
}
