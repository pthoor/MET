[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'METCheckInfo',
    Justification = 'Check metadata. Read from the AST by Get-METCheck and never executed.')]
param()

$METCheckInfo = @{
    Name           = 'Cross-Tenant Guest & External Collaboration Restrictions'
    Severity       = 'Medium'
    Description    = 'Checks the Microsoft Graph cross-tenant access default policy and authorization policy for guest invitation and external collaboration settings.'
    RequiresModule = @('Microsoft.Graph')
}

$defaultPolicy = $null
$authPolicy = $null

# This is the first MET check with a direct Microsoft Graph dependency (every prior Graph
# call site lives in the private Expand-METGroupMembership helper, not a check body). There
# is no Exchange Online or native Teams-module equivalent for Entra's cross-tenant access
# default policy, so per CLAUDE.md's bar for a direct Graph dependency this is justified -
# but it must still degrade non-fatally to NotApplicable rather than aborting the run,
# mirroring Expand-METGroupMembership's try/catch pattern.
#
# Two distinct "could not run" cases, deliberately reported differently:
#   1. Graph was never connected (-SkipGraph, the Microsoft.Graph.Identity.SignIns module
#      absent, or the known EXO/Graph MSAL conflict at Connect-METSession). This is an
#      expected, documented degradation - the reason goes in Finding, NOT the Error field,
#      so a routine -SkipGraph run does not park this check in the report's Error bucket.
#   2. Graph is connected but a policy call failed (most often a missing Policy.Read.All
#      scope). That is an unexpected failure worth surfacing, so the Error field is set.
$graphCmdletsAvailable =
    [bool](Get-Command -Name Get-MgPolicyCrossTenantAccessPolicyDefault -ErrorAction SilentlyContinue) -and
    [bool](Get-Command -Name Get-MgPolicyAuthorizationPolicy -ErrorAction SilentlyContinue)

if (-not $graphCmdletsAvailable) {
    New-METCheckResult -CheckId 'MET-Teams014' -Category Teams `
        -Name 'Cross-Tenant Guest & External Collaboration Restrictions' `
        -Result NotApplicable -Severity Medium `
        -AffectedObject 'Cross-Tenant Access Policy' `
        -Finding 'Microsoft Graph was not connected for this run, so the Entra ID cross-tenant access default policy and authorization policy could not be retrieved and this check could not run. This is not a failure - it is skipped whenever Connect-METSession runs with -SkipGraph, without the Microsoft.Graph.Identity.SignIns module installed, or when the Graph connection could not be established.' `
        -Recommendation 'To include this check, run Connect-METSession without -SkipGraph, with the Microsoft.Graph.Identity.SignIns module (2.x) installed and the Policy.Read.All scope consented, then re-run.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/graph/api/crosstenantaccesspolicy-get'
    return
}

try {
    $defaultPolicy = Get-MgPolicyCrossTenantAccessPolicyDefault -ErrorAction Stop
    $authPolicy = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop
}
catch {
    Write-Verbose "Cross-tenant access policy retrieval via Microsoft Graph failed: $_"

    if ($_.Exception -is [System.Management.Automation.CommandNotFoundException]) {
        # The cmdlet resolved a moment ago but the call reports it as unknown - treat this
        # as Graph-not-connected (case 1), not a check error.
        New-METCheckResult -CheckId 'MET-Teams014' -Category Teams `
            -Name 'Cross-Tenant Guest & External Collaboration Restrictions' `
            -Result NotApplicable -Severity Medium `
            -AffectedObject 'Cross-Tenant Access Policy' `
            -Finding 'Microsoft Graph was not connected for this run, so the Entra ID cross-tenant access default policy and authorization policy could not be retrieved and this check could not run. This is not a failure - it is skipped whenever Connect-METSession runs with -SkipGraph, without the Microsoft.Graph.Identity.SignIns module installed, or when the Graph connection could not be established.' `
            -Recommendation 'To include this check, run Connect-METSession without -SkipGraph, with the Microsoft.Graph.Identity.SignIns module (2.x) installed and the Policy.Read.All scope consented, then re-run.' `
            -ReferenceUrl 'https://learn.microsoft.com/en-us/graph/api/crosstenantaccesspolicy-get'
        return
    }

    New-METCheckResult -CheckId 'MET-Teams014' -Category Teams `
        -Name 'Cross-Tenant Guest & External Collaboration Restrictions' `
        -Result NotApplicable -Severity Medium `
        -AffectedObject 'Cross-Tenant Access Policy' `
        -Finding 'Microsoft Graph is connected, but retrieving the Entra ID cross-tenant access default policy or authorization policy failed, so this check could not run. The signed-in identity most likely lacks the Policy.Read.All scope.' `
        -Recommendation 'Grant the Policy.Read.All scope to the identity MET connects with, then re-run. In the Entra admin center the same settings are under External Identities > Cross-tenant access settings.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/graph/api/crosstenantaccesspolicy-get' `
        -ErrorMessage $_.ToString()
    return
}

$findings = [System.Collections.Generic.List[string]]::new()
$evaluated = $false
$hasConcern = $false

# --- Default cross-tenant access policy: inbound B2B collaboration/direct connect ---
if ($null -ne $defaultPolicy) {
    $isServiceDefaultProp = $defaultPolicy.PSObject.Properties['IsServiceDefault']
    if ($isServiceDefaultProp -and $isServiceDefaultProp.Value -eq $true) {
        $evaluated = $true
        $hasConcern = $true
        $findings.Add('The default cross-tenant access policy has not been customized (IsServiceDefault=true) - the tenant is relying on the Microsoft Entra system default, which permits inbound and outbound B2B collaboration with any external Microsoft Entra organization unless explicitly restricted')
    }

    foreach ($direction in @('B2BCollaborationInbound', 'B2BCollaborationOutbound', 'B2BDirectConnectInbound', 'B2BDirectConnectOutbound')) {
        $directionProp = $defaultPolicy.PSObject.Properties[$direction]
        if (-not $directionProp -or $null -eq $directionProp.Value) { continue }
        $setting = $directionProp.Value

        foreach ($scope in @('UsersAndGroups', 'Applications')) {
            $scopeProp = $setting.PSObject.Properties[$scope]
            if (-not $scopeProp -or $null -eq $scopeProp.Value) { continue }
            $scopeValue = $scopeProp.Value

            $accessTypeProp = $scopeValue.PSObject.Properties['AccessType']
            if (-not $accessTypeProp -or $null -eq $accessTypeProp.Value) { continue }
            $evaluated = $true

            if ([string]$accessTypeProp.Value -eq 'allowed' -and $direction -like '*Inbound*') {
                $targetDescription = 'no explicit target restriction'
                $targetsProp = $scopeValue.PSObject.Properties['Targets']
                if ($targetsProp -and $targetsProp.Value) {
                    $targetNames = @($targetsProp.Value | ForEach-Object { $_.Target }) -join ', '
                    if ($targetNames) { $targetDescription = "targets: $targetNames" }
                }
                $hasConcern = $true
                $findings.Add("$direction ($scope) is set to Allowed ($targetDescription) - external users, groups, or applications from unconfigured/unknown external tenants can access your organization's resources via this path by default")
            }
        }
    }
}

# --- Authorization policy: who can invite guests ---
if ($null -ne $authPolicy) {
    $allowInvitesProp = $authPolicy.PSObject.Properties['AllowInvitesFrom']
    if ($allowInvitesProp -and $allowInvitesProp.Value) {
        $evaluated = $true
        if ([string]$allowInvitesProp.Value -eq 'everyone') {
            $hasConcern = $true
            $findings.Add("AllowInvitesFrom is set to 'everyone' - any user in the organization, including existing guests, can invite new external guests without administrator review")
        }
    }
}

if (-not $evaluated) {
    New-METCheckResult -CheckId 'MET-Teams014' -Category Teams `
        -Name 'Cross-Tenant Guest & External Collaboration Restrictions' `
        -Result Info -Severity Medium `
        -AffectedObject 'Cross-Tenant Access Policy' `
        -Finding 'Retrieved the default cross-tenant access policy and authorization policy from Microsoft Graph, but could not identify any recognizable settings (IsServiceDefault, B2B collaboration/direct connect inbound-outbound access type, or AllowInvitesFrom) to evaluate a Pass/Fail condition. The returned objects may be from an unexpected module version or shape - manual review is required.' `
        -Recommendation 'Review the cross-tenant access default policy and authorization policy manually in the Entra admin center (entra.microsoft.com) > External Identities > Cross-tenant access settings.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/graph/api/crosstenantaccesspolicy-get'
    return
}

if ($hasConcern) {
    New-METCheckResult -CheckId 'MET-Teams014' -Category Teams `
        -Name 'Cross-Tenant Guest & External Collaboration Restrictions' `
        -Result Warning -Severity Medium `
        -AffectedObject 'Cross-Tenant Access Policy' `
        -Finding ($findings -join '; ') `
        -Recommendation 'Review and scope the default cross-tenant access policy in the Entra admin center (entra.microsoft.com) > External Identities > Cross-tenant access settings > Default settings. Restrict inbound B2B collaboration/direct connect access to explicit organizations, users, or groups rather than relying on the open system default, and set AllowInvitesFrom to a more restrictive value (e.g. adminsAndGuestInviters) unless broad guest-invite rights are a deliberate business decision. Use Update-MgPolicyCrossTenantAccessPolicyDefault and Update-MgPolicyAuthorizationPolicy to remediate.' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/graph/api/crosstenantaccesspolicy-get'
}
else {
    New-METCheckResult -CheckId 'MET-Teams014' -Category Teams `
        -Name 'Cross-Tenant Guest & External Collaboration Restrictions' `
        -Result Pass -Severity Medium `
        -AffectedObject 'Cross-Tenant Access Policy' `
        -Finding 'The default cross-tenant access policy is customized and inbound B2B collaboration/direct connect settings and guest-invite rights do not indicate open, unrestricted external collaboration' `
        -ReferenceUrl 'https://learn.microsoft.com/en-us/graph/api/crosstenantaccesspolicy-get'
}
