# MET-Teams010 - Per-User External Access Policy Drift

**Category:** Teams | **Severity:** Medium

## What it checks

Compares every **non-Global** `CsExternalAccessPolicy` returned by `Get-CsExternalAccessPolicy` with the **Global** policy. It flags a custom policy that turns on something the Global policy turns off:

| Property | What it allows |
|---|---|
| `EnableFederationAccess` | Chat, calls and meetings with users in external Microsoft 365 organizations |
| `EnableTeamsConsumerAccess` | Chat with people using Teams on an account no organization manages (personal Microsoft accounts) |
| `EnableTeamsConsumerInbound` | Those personal accounts can find the user and start the conversation |

All three default to `$true`. A custom policy with one of them on is only drift if the Global policy turns it off. A custom policy that matches an open Global policy isn't flagged, because it doesn't widen anything. `EnableTeamsConsumerInbound` is ignored on a policy that has `EnableTeamsConsumerAccess` off, because inbound does nothing without access.

Per-user policies sit underneath the tenant-wide settings in `Get-CsTenantFederationConfiguration` (MET-Teams006). A user can only communicate externally when both allow it. A custom policy re-opening personal-account chat therefore only takes effect while the tenant-level `AllowTeamsConsumer` is on.

Earlier versions also read `EnablePublicCloudAccess` and flagged federation regardless of the Global value. `EnablePublicCloudAccess` isn't on the current `Set-CsExternalAccessPolicy` syntax and isn't returned by MicrosoftTeams 7.9.0, so it's no longer read. The old federation logic also warned about "undoing a restriction on the Global policy" when the Global policy was open, so federation is now compared with the Global policy too.

## Why it matters

Tenant-wide restrictions give a false sense of security if per-user policies aren't also reviewed. An administrator can lock the Global policy down to satisfy an audit while an older or forgotten custom policy, assigned to a department, a pilot group or a finished project, still lets that user set federate freely or chat with personal accounts. Attackers who work out which users are exempt from the restriction can target them specifically. Teams-based social engineering already benefits from the trust users place in what looks like an internal collaboration tool, and personal-account first contact is the opening move of most Teams phishing and vishing lures.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | No non-Global policy turns on a property the Global policy turns off. Also Pass when no non-Global policy exists, or no policies are returned at all |
| Warning | A non-Global policy turns on a property the Global policy turns off, or doesn't return a property the Global policy turns off. One Warning per policy, named by its `Identity` |
| NotApplicable | Non-Global policies exist but the Global policy (or one of the three properties on it) wasn't returned, so there was no baseline to compare against. Emitted alongside the other results, never replaced by a Pass |
| Fail | `Get-CsExternalAccessPolicy` could not be retrieved (insufficient permissions, Teams module unavailable) |

## Recommendation

Close what the Global policy closes, unless the user set has a specific business need:

```powershell
Set-CsExternalAccessPolicy -Identity '<policy>' -EnableFederationAccess $false
Set-CsExternalAccessPolicy -Identity '<policy>' -EnableTeamsConsumerAccess $false -EnableTeamsConsumerInbound $false
```

Where staff genuinely need to chat with personal accounts (recruiters, for example), keep `-EnableTeamsConsumerInbound $false` so personal accounts can't start the conversation.

Before changing scope, identify who is affected:

```powershell
Get-CsOnlineUser -Filter "ExternalAccessPolicy -eq '<policy>'"
```

## Reference

- [Get-CsExternalAccessPolicy](https://learn.microsoft.com/en-us/powershell/module/microsoftteams/get-csexternalaccesspolicy)
- [Set-CsExternalAccessPolicy](https://learn.microsoft.com/en-us/powershell/module/microsoftteams/set-csexternalaccesspolicy)
