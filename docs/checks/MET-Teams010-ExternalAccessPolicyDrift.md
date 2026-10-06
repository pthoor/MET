# MET-Teams010 - Per-User External Access Policy Drift

**Category:** Teams | **Severity:** Medium

## What it checks

Reviews every per-user `CsExternalAccessPolicy` returned by `Get-CsExternalAccessPolicy`, not just the Global/default policy:

- Any **non-Global** policy where `EnableFederationAccess` is `$true` or `EnablePublicCloudAccess` is `$true` is flagged. A non-Global external access policy re-opens federation or public-cloud access for whoever it is assigned to - silently undoing a tenant-wide federation restriction that was locked down at the `CsTenantFederationConfiguration` level (evaluated separately by MET-Teams006).
- **Unmanaged (personal) account drift.** `EnableTeamsConsumerAccess` decides whether a user can chat with people using Teams on an account no organization manages. `EnableTeamsConsumerInbound` decides whether those people can find the user and start the conversation. Both default to `$true`, so a custom policy having them on is not a finding by itself. A non-Global policy is flagged only when it turns on a property that the **Global** policy turns off. `EnableTeamsConsumerInbound` is ignored when the same policy has `EnableTeamsConsumerAccess` off, because inbound does nothing without access. These per-user settings only take effect while the tenant-level `AllowTeamsConsumer` is on (MET-Teams006).

**Property-confirmation caveat:** as of this writing, Microsoft Learn's `Get-CsExternalAccessPolicy` reference page does not publish a full parameter/output-property table (it is an older cmdlet page without one). The only properties confirmed by the docs' own usage examples are `EnableFederationAccess` and `EnablePublicCloudAccess` - e.g. `Get-CsExternalAccessPolicy | Where-Object {$_.EnableFederationAccess -eq $True -and $_.EnablePublicCloudAccess -eq $True}`. The federation part of this check is built against only those two properties. The unmanaged-account properties (`EnableTeamsConsumerAccess`, `EnableTeamsConsumerInbound`) are documented on the `Set-CsExternalAccessPolicy` reference, both with a default of `$true`. Note that the current `Set-CsExternalAccessPolicy` syntax lists `EnablePublicCloudAudioVideoAccess` but not `EnablePublicCloudAccess`, so `EnablePublicCloudAccess` may not be returned on current module versions.

This is a **separate control plane** from MET-Teams006. Teams006 evaluates the tenant-wide `CsTenantFederationConfiguration` (the ceiling for the whole org). This check evaluates per-user/per-group `CsExternalAccessPolicy` assignments, which can carve out an exception underneath that ceiling for a specific set of users - for example, a "Sales-Federation" policy that re-enables federation for the sales team even though the Global policy is locked down.

## Why it matters

Tenant-wide federation restrictions give a false sense of security if per-user policies aren't also reviewed. An administrator can lock `AllowedDomains` down at the tenant level to satisfy an audit, while an older or forgotten per-user policy (assigned to a specific department, pilot group, or a former project) continues to allow that user set to federate freely or reach public-cloud (consumer) accounts. Attackers who identify which users are exempted from the tenant-wide restriction can specifically target them, since Teams-based social engineering already benefits from the implicit trust users place in what looks like an internal collaboration tool.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | No non-Global external access policy exists, or none of the non-Global policies has `EnableFederationAccess` or `EnablePublicCloudAccess` set to `$true` or re-opens unmanaged-account access the Global policy closes. Also Pass if zero policies are returned at all |
| Warning | One or more non-Global policies have `EnableFederationAccess` and/or `EnablePublicCloudAccess` set to `$true`, or turn on `EnableTeamsConsumerAccess`/`EnableTeamsConsumerInbound` that the Global policy turns off, or don't return those properties while the Global policy has them off. One Warning per flagged policy, named by its `Identity` |
| NotApplicable | Non-Global policies exist but the Global policy didn't return `EnableTeamsConsumerAccess`/`EnableTeamsConsumerInbound`, so there was no baseline to compare against. Emitted alongside the federation result, never as a Pass |
| Fail | `Get-CsExternalAccessPolicy` could not be retrieved (e.g. insufficient permissions, Teams module unavailable) |

## Recommendation

Review non-Global external access policies and disable `EnableFederationAccess`/`EnablePublicCloudAccess` unless there's a specific business need for that user set to bypass tenant-wide federation restrictions. Run `Get-CsOnlineUser -Filter "ExternalAccessPolicy -eq '<policy>'"` to identify affected users before changing scope.

For unmanaged-account drift, close what the Global policy closes unless the user set has a specific need:

```powershell
Set-CsExternalAccessPolicy -Identity '<policy>' -EnableTeamsConsumerAccess $false -EnableTeamsConsumerInbound $false
```

Where staff genuinely need to chat with personal accounts (recruiters, for example), keep `-EnableTeamsConsumerInbound $false` so personal accounts can't start the conversation.

## Reference

- [Get-CsExternalAccessPolicy](https://learn.microsoft.com/en-us/powershell/module/microsoftteams/get-csexternalaccesspolicy)
- [Set-CsExternalAccessPolicy](https://learn.microsoft.com/en-us/powershell/module/microsoftteams/set-csexternalaccesspolicy)
