# MET-Teams006 - External Access / Federation Allow-List

**Category:** Teams | **Severity:** High

## What it checks

Reviews the tenant's Teams federation (external access) configuration via `Get-CsTenantFederationConfiguration`:

- **Open federation** - `AllowFederatedUsers` is enabled and `AllowedDomains` is set to `AllowAllKnownDomains`, meaning any external Teams tenant can attempt to federate with yours
- **Consumer/personal accounts** - `AllowTeamsConsumer` is enabled, allowing Teams accounts not managed by any organization (personal Microsoft accounts) to federate with your users

This is a **separate control plane** from meeting-level protections covered by MET-Teams003. Meeting protection (anonymous join, lobby bypass) governs who can get into a *scheduled meeting*. Federation governs whether an external Teams user can *initiate a 1:1 or group chat* with your staff at all - before any meeting is ever scheduled. A user can be blocked from joining meetings anonymously and still receive an unsolicited chat message from an external account if federation is wide open.

## Why it matters

Federation is a growing vector for Teams-based phishing, vishing, and QR-code lures: an attacker registers (or compromises) any Microsoft 365 or personal Teams account, then messages your staff directly, impersonating IT support, a vendor, or an executive. Because Teams chat carries an implicit trust signal (it looks like an internal collaboration tool, not email), users are often less suspicious of an unsolicited Teams message than an unsolicited email. Leaving `AllowedDomains` at `AllowAllKnownDomains` means every one of the millions of Microsoft 365 tenants worldwide - plus, if `AllowTeamsConsumer` is also enabled, every personal Teams/Skype account - can attempt to reach your users with no allow-list review at all.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | Federation is scoped to a specific, reviewed domain allow-list (not `AllowAllKnownDomains`) and consumer/personal account federation is disabled |
| Fail | `AllowedDomains` is `AllowAllKnownDomains` while `AllowFederatedUsers` is enabled - federation is open to any external domain |
| Warning | `AllowTeamsConsumer` is enabled (with federation otherwise scoped), or the tenant federation configuration could not be retrieved |

## Recommendation

Restrict `AllowedDomains` to a specific, reviewed allow-list of trusted partner domains instead of `AllowAllKnownDomains`. Disable `AllowTeamsConsumer` unless there is a specific business need for staff to chat with personal Teams/Skype accounts. Run `Set-CsTenantFederationConfiguration -AllowedDomains <AllowedDomainsObject>` to scope federation, or `-AllowFederatedUsers $false` to disable it entirely.

## Reference

- [Set-CsTenantFederationConfiguration](https://learn.microsoft.com/en-us/powershell/module/microsoftteams/set-cstenantfederationconfiguration)
