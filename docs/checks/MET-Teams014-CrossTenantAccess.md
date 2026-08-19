# MET-Teams014 - Cross-Tenant Guest & External Collaboration Restrictions

**Category:** Teams | **Severity:** Medium

## What it checks

Reviews Entra ID's cross-tenant access configuration via Microsoft Graph:

- **Default cross-tenant access policy** (`Get-MgPolicyCrossTenantAccessPolicyDefault`) - whether the tenant relies on the unmodified Microsoft system default (`IsServiceDefault = $true`), and whether inbound B2B collaboration or B2B direct connect (`B2BCollaborationInbound`, `B2BDirectConnectInbound`) is set to `Allowed` for users/groups or applications with no explicit target restriction. This governs whether external users from *unconfigured/unknown* external Microsoft Entra tenants can access your organization's resources at all - before any partner-specific override is considered.
- **Authorization policy guest-invite rights** (`Get-MgPolicyAuthorizationPolicy`) - whether `AllowInvitesFrom` is set to `everyone`, letting any user (including existing guests) invite new external guests without administrator review.

Property presence is checked defensively (`PSObject.Properties` existence checks, never a direct dotted access on an assumed shape) before any value is read, so an unexpected or evolving Graph object shape produces an `Info` result surfacing that the data could not be evaluated, rather than a wrong Pass/Fail guess or a crash.

**This is the first MET check with a direct, non-degrading-to-EXO Microsoft Graph dependency.** Every prior Graph call site lives inside the private `Expand-METGroupMembership` helper, which itself falls back to Exchange Online cmdlets when Graph is unavailable. No Exchange Online or native Teams-module cmdlet exposes Entra's cross-tenant access policy, so there is no non-Graph data source to fall back to here. Per `CLAUDE.md`'s "Connection Requirements for New Checks," this check therefore degrades to a single `NotApplicable` result - not a thrown error - whenever Graph is unavailable (module not installed, `Connect-METSession -SkipGraph` was used, the session's Graph connection failed, or the call itself throws for any other reason). It never aborts `Invoke-METTriage`.

This is a **distinct control plane** from two existing Teams checks that sound similar:

- **MET-Teams006** (External Access / Federation) checks Teams-to-Teams federation via `Get-CsTenantFederationConfiguration` - whether external Teams users can chat with your staff.
- **MET-Teams007** (Guest Messaging/Calling) checks whether guests already admitted to your tenant can initiate chat or calls.
- **MET-Teams014** (this check) sits one layer beneath both: it governs whether an external Microsoft Entra identity can access your tenant's resources (Teams, SharePoint, and other Microsoft 365 workloads) as a B2B guest or B2B direct connect user in the first place, and who is allowed to invite them.

## Why it matters

Cross-tenant access settings are the outermost gate for B2B collaboration. Microsoft Entra's default (system) configuration permits inbound and outbound B2B collaboration with any external Microsoft Entra organization unless the tenant has explicitly customized the default policy or added partner-specific restrictions. A tenant that has never reviewed this setting (`IsServiceDefault = $true`) is implicitly trusting every other Microsoft Entra tenant in the world for B2B collaboration. Combined with `AllowInvitesFrom = everyone`, any user in the organization - not just administrators - can extend that trust further by inviting new external guests, with no review step. Together these two settings define how easily an attacker who compromises a single account (internal or already-guest) can pull outside identities into the tenant's collaboration surface.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | The default cross-tenant access policy is customized (`IsServiceDefault = $false`) or its inbound settings are explicitly evaluated and not open, and `AllowInvitesFrom` is not `everyone` |
| Warning | The default policy is unmodified (`IsServiceDefault = $true`), inbound B2B collaboration/direct connect is `Allowed` with no target restriction, and/or `AllowInvitesFrom` is `everyone` |
| Info | Graph returned data but no recognizable property (`IsServiceDefault`, an inbound `AccessType`, or `AllowInvitesFrom`) could be found to evaluate - manual review needed |
| NotApplicable | Microsoft Graph is unavailable - module not installed, `Connect-METSession` was run with `-SkipGraph`, the Graph connection failed, or the underlying cmdlet call threw |

## Recommendation

Review and scope the default cross-tenant access policy in the Entra admin center (entra.microsoft.com) > External Identities > Cross-tenant access settings > Default settings. Restrict inbound B2B collaboration/direct connect access to explicit organizations, users, or groups rather than relying on the open system default, and set `AllowInvitesFrom` to a more restrictive value (e.g. `adminsAndGuestInviters`) unless broad guest-invite rights are a deliberate business decision. Remediate via `Update-MgPolicyCrossTenantAccessPolicyDefault` and `Update-MgPolicyAuthorizationPolicy`.

## Reference

- [Get crossTenantAccessPolicyConfigurationDefault](https://learn.microsoft.com/en-us/graph/api/crosstenantaccesspolicy-get)
