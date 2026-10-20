function Get-METGraphScope {
    # The delegated scopes Connect-METSession requests, shared with Test-METPrerequisites
    # -TestConnection so the preflight cannot drift from what is actually requested.
    # The only Graph call sites are Expand-METGroupMembership.ps1 (Get-MgGroup/
    # Get-MgGroupTransitiveMember, covered by Group.Read.All) and MET-Teams014
    # (Get-MgPolicyCrossTenantAccessPolicyDefault/Get-MgPolicyAuthorizationPolicy, covered by
    # Policy.Read.All). User.Read.All and Organization.Read.All are deliberately not requested:
    # neither is needed, and one unconsented scope is enough to send the whole sign-in to an
    # admin consent prompt in a tenant that consented to the rest.
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    @(
        'Policy.Read.All'
        'Group.Read.All'
    )
}
