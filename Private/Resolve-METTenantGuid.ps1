function Resolve-METTenantGuid {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $TenantId
    )

    if ($TenantId -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
        return $TenantId
    }

    # Domain names (e.g. contoso.onmicrosoft.com) don't compare against the GUID that
    # Get-MgContext/Get-CsTenant return, so resolve via the tenant's own unauthenticated
    # OpenID Connect discovery document - the standard way to map a domain to its tenant
    # GUID without needing an existing Graph/Teams session (avoids a chicken-and-egg
    # problem when the very thing being checked is whether that session is trustworthy).
    try {
        $discovery = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/v2.0/.well-known/openid-configuration" -ErrorAction Stop
        if ($discovery.issuer -match '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})') {
            return $Matches[1]
        }
    }
    catch {
        Write-Verbose "Unable to resolve tenant GUID for '$TenantId': $_"
    }

    return $null
}
