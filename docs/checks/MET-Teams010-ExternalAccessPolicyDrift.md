# MET-Teams010 - Per-User External Access Policy Drift

**Category:** Teams | **Severity:** Medium

## What it checks

Reviews every per-user `CsExternalAccessPolicy` returned by `Get-CsExternalAccessPolicy`, not just the Global/default policy:

- Any **non-Global** policy where `EnableFederationAccess` is `$true` or `EnablePublicCloudAccess` is `$true` is flagged. A non-Global external access policy re-opens federation or public-cloud access for whoever it is assigned to - silently undoing a tenant-wide federation restriction that was locked down at the `CsTenantFederationConfiguration` level (evaluated separately by MET-Teams006).

**Property-confirmation caveat:** as of this writing, Microsoft Learn's `Get-CsExternalAccessPolicy` reference page does not publish a full parameter/output-property table (it is an older cmdlet page without one). The only properties confirmed by the docs' own usage examples are `EnableFederationAccess` and `EnablePublicCloudAccess` - e.g. `Get-CsExternalAccessPolicy | Where-Object {$_.EnableFederationAccess -eq $True -and $_.EnablePublicCloudAccess -eq $True}`. This check is deliberately built against only those two confirmed properties. If a live tenant reveals additional relevant properties on newer `MicrosoftTeams` module versions (e.g. finer-grained consumer/Skype controls), this check may need extending once those properties are confirmed against current documentation.

This is a **separate control plane** from MET-Teams006. Teams006 evaluates the tenant-wide `CsTenantFederationConfiguration` (the ceiling for the whole org). This check evaluates per-user/per-group `CsExternalAccessPolicy` assignments, which can carve out an exception underneath that ceiling for a specific set of users - for example, a "Sales-Federation" policy that re-enables federation for the sales team even though the Global policy is locked down.

## Why it matters

Tenant-wide federation restrictions give a false sense of security if per-user policies aren't also reviewed. An administrator can lock `AllowedDomains` down at the tenant level to satisfy an audit, while an older or forgotten per-user policy (assigned to a specific department, pilot group, or a former project) continues to allow that user set to federate freely or reach public-cloud (consumer) accounts. Attackers who identify which users are exempted from the tenant-wide restriction can specifically target them, since Teams-based social engineering already benefits from the implicit trust users place in what looks like an internal collaboration tool.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | No non-Global external access policy exists, or none of the non-Global policies have `EnableFederationAccess` or `EnablePublicCloudAccess` set to `$true`; also Pass if zero policies are returned at all |
| Warning | One or more non-Global policies have `EnableFederationAccess` and/or `EnablePublicCloudAccess` set to `$true` - one Warning result is emitted per flagged policy, named by its `Identity` |
| Fail | `Get-CsExternalAccessPolicy` could not be retrieved (e.g. insufficient permissions, Teams module unavailable) |

## Recommendation

Review non-Global external access policies and disable `EnableFederationAccess`/`EnablePublicCloudAccess` unless there's a specific business need for that user set to bypass tenant-wide federation restrictions. Run `Get-CsOnlineUser -Filter "ExternalAccessPolicy -eq '<policy>'"` to identify affected users before changing scope.

## Reference

- [Get-CsExternalAccessPolicy](https://learn.microsoft.com/en-us/powershell/module/microsoftteams/get-csexternalaccesspolicy)
