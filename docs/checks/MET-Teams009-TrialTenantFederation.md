# MET-Teams009 - Trial Tenant Federation Exposure

**Category:** Teams | **Severity:** High

## What it checks

Reviews the tenant's Teams federation configuration via `Get-CsTenantFederationConfiguration`, specifically the `ExternalAccessWithTrialTenants` setting (an `ExternalAccessWithTrialTenantsType` string enum with values `Allowed` or `Blocked`):

- **Trial tenant communication allowed** - `ExternalAccessWithTrialTenants` is `Allowed`, meaning users on unlicensed/trial Microsoft 365 tenants can initiate Teams chats and calls with your users
- **Trial tenant communication blocked** - `ExternalAccessWithTrialTenants` is `Blocked`, the secure default posture
- **Allow-listed trial domains** - if `AllowedTrialTenantDomains` is populated, those specific trial-tenant domains are surfaced in the finding as a deliberate, reviewed exception rather than a blind gap, regardless of the overall result

This is a **separate control plane** from MET-Teams006 (general federation domain allow-listing). `AllowedDomains`/`AllowAllKnownDomains` governs federation with established, licensed Microsoft 365 tenants. `ExternalAccessWithTrialTenants` governs federation specifically with trial/unlicensed tenants, which can be created for free in minutes and discarded just as quickly - a materially different (and cheaper to abuse) risk profile than a long-lived, licensed organization.

## Why it matters

Trial tenants are trivial to spin up disposably: no payment method, no lasting organizational footprint, and no reputation history. This makes them a known first-contact vector for phishing and vishing campaigns in the style of threat actors like Storm-1811 - an attacker registers a fresh, clean-looking trial tenant, uses it once to reach your users via an unsolicited Teams chat or call (often impersonating IT support or a help desk), and abandons the tenant immediately after the attempt, leaving little to nothing to block or attribute retroactively. Because the message arrives inside Teams rather than email, it also benefits from the same implicit-trust blind spot described in MET-Teams006: users are generally less suspicious of an unsolicited Teams message than an unsolicited email.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | `ExternalAccessWithTrialTenants` is `Blocked` |
| Fail | `ExternalAccessWithTrialTenants` is `Allowed`, or the tenant federation configuration could not be retrieved |
| Warning | `ExternalAccessWithTrialTenants` is `$null` or an unrecognized value - inconclusive, requires manual verification |

## Recommendation

Run `Set-CsTenantFederationConfiguration -ExternalAccessWithTrialTenants Blocked` to prevent trial/unlicensed tenants from initiating Teams communication with your users. If a legitimate business need exists for specific trial-tenant partners (e.g. a vendor evaluating Microsoft 365 before purchasing licenses), use `AllowedTrialTenantDomains` to scope the exception to those specific domains instead of leaving trial tenant access open tenant-wide.

## Reference

- [Set-CsTenantFederationConfiguration](https://learn.microsoft.com/en-us/powershell/module/microsoftteams/set-cstenantfederationconfiguration)
