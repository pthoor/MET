# MET-Teams006 - External Access / Federation Allow-List

**Category:** Teams | **Severity:** High

## What it checks

Reviews the tenant's Teams federation (external access) configuration via `Get-CsTenantFederationConfiguration`:

- **Open federation** - `AllowFederatedUsers` is enabled and `AllowedDomains` is set to `AllowAllKnownDomains`, meaning any external Teams tenant can attempt to federate with yours
- **Consumer/personal accounts** - `AllowTeamsConsumer` is enabled, allowing Teams accounts not managed by any organization (personal Microsoft accounts) to federate with your users
- **Consumer inbound direction** - when `AllowTeamsConsumer` is enabled, `AllowTeamsConsumerInbound` determines *which direction* that federation can be initiated. Its default value is `$true` (unset/`$null` is treated as open by this check). When `$true`, unmanaged personal accounts can discover and start a conversation with your staff - the higher-risk direction. When explicitly set to `$false`, only your staff can initiate contact with personal accounts; personal accounts cannot discover or message your users first, which meaningfully lowers (but does not eliminate) the risk of `AllowTeamsConsumer` being enabled
- **Consumer profile restriction** - `RestrictTeamsConsumerToExternalUserProfiles`, if present on the returned object (older module versions may not expose it), further narrows consumer interaction to external user profiles in the Extended Directory rather than any arbitrary personal account, when enabled
- **Deny-list hygiene** - when `AllowFederatedUsers` is enabled and `BlockedDomains` is empty, there is no explicit domain-level deny-list configured as a defense-in-depth backstop

This is a **separate control plane** from meeting-level protections covered by MET-Teams003. Meeting protection (anonymous join, lobby bypass) governs who can get into a *scheduled meeting*. Federation governs whether an external Teams user can *initiate a 1:1 or group chat* with your staff at all - before any meeting is ever scheduled. A user can be blocked from joining meetings anonymously and still receive an unsolicited chat message from an external account if federation is wide open.

## Why it matters

Federation is a growing vector for Teams-based phishing, vishing, and QR-code lures: an attacker registers (or compromises) any Microsoft 365 or personal Teams account, then messages your staff directly, impersonating IT support, a vendor, or an executive. Because Teams chat carries an implicit trust signal (it looks like an internal collaboration tool, not email), users are often less suspicious of an unsolicited Teams message than an unsolicited email. Leaving `AllowedDomains` at `AllowAllKnownDomains` means every one of the millions of Microsoft 365 tenants worldwide - plus, if `AllowTeamsConsumer` is also enabled with `AllowTeamsConsumerInbound` left at its default `$true` - every personal Teams/Skype account - can attempt to reach your users with no allow-list review at all. Setting `AllowTeamsConsumerInbound $false` does not remove the exposure entirely (staff can still be socially engineered into starting an outbound chat) but it closes off the unsolicited-first-contact path, which is the pattern most consumer-account phishing lures rely on. An empty `BlockedDomains` list is a smaller gap on its own, but it means there is no deny-list ready to take effect if the allow-list scope is ever broadened back to `AllowAllKnownDomains`.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | Federation is scoped to a specific, reviewed domain allow-list (not `AllowAllKnownDomains`), consumer/personal account federation is disabled, and a `BlockedDomains` deny-list is populated |
| Fail | `AllowedDomains` is `AllowAllKnownDomains` while `AllowFederatedUsers` is enabled - federation is open to any external domain |
| Warning | `AllowTeamsConsumer` is enabled (with federation otherwise scoped) - the finding text distinguishes whether `AllowTeamsConsumerInbound` is open (personal accounts can initiate first contact, the higher-risk case) or blocked (partially mitigated - outbound-only) and notes when `RestrictTeamsConsumerToExternalUserProfiles` further narrows exposure; or `AllowFederatedUsers` is enabled with an empty `BlockedDomains` deny-list; or the tenant federation configuration could not be retrieved |

## Recommendation

Restrict `AllowedDomains` to a specific, reviewed allow-list of trusted partner domains instead of `AllowAllKnownDomains`, and configure a `BlockedDomains` deny-list as a defense-in-depth backstop. Disable `AllowTeamsConsumer` unless there is a specific business need for staff to chat with personal Teams/Skype accounts; if it must stay enabled, run `Set-CsTenantFederationConfiguration -AllowTeamsConsumerInbound $false` so personal/consumer accounts cannot discover or initiate contact with your organization, and consider `-RestrictTeamsConsumerToExternalUserProfiles $true` to further narrow exposure. Run `Set-CsTenantFederationConfiguration -AllowedDomains <AllowedDomainsObject>` to scope federation, or `-AllowFederatedUsers $false` to disable it entirely.

## Reference

- [Set-CsTenantFederationConfiguration](https://learn.microsoft.com/en-us/powershell/module/microsoftteams/set-cstenantfederationconfiguration)
