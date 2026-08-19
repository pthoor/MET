# MET-Teams011 - SecOps Blocklist Authority & Blocked Entities

**Category:** Teams | **Severity:** Medium

## What it checks

Reviews whether the security team can respond to an active Teams-based incident directly from the Defender security portal, and surfaces what is currently blocked, using two independent data sources:

- **`Get-CsTenantFederationConfiguration`** - reads `SecurityTeamAllowBlockListDelegation`, a string enum (`Enabled` / `Disabled`, default `Disabled`) that controls whether SecOps can add a malicious external domain or user to the Teams block list from the Defender security portal, without needing PowerShell access.
- **`Get-CsTeamsExternalAccessConfiguration`** - a separate, current cmdlet distinct from `Get-CsTenantFederationConfiguration`. Its `BlockedUsers` property lists users currently blocked from external access, added here as informational context alongside the delegation finding.

This is a **response-readiness check**, not a hard security-posture Fail. It answers "if my SecOps team spots a malicious external domain or user mid-incident, can they block it themselves from the portal, or do they have to find someone with PowerShell access first?" - a meaningful difference in mean-time-to-contain during an active attack.

The two cmdlets are queried independently, each in its own try/catch. If one fails, the check still produces the best possible result from whichever succeeded; only if both fail does the check emit a hard Fail with the combined error detail.

## Why it matters

During an active Teams-based phishing or vishing incident, minutes matter. If `SecurityTeamAllowBlockListDelegation` is left at its default (`Disabled`), the security team's only remediation path is to find someone with `Set-CsTenantFederationConfiguration` PowerShell access and Teams administrator rights - which may not be the person watching the incident unfold in the Defender portal. Enabling delegation lets SecOps block a malicious domain or user the moment it's identified, without a hand-off delay.

The current `BlockedUsers` count is surfaced as context, not as a pass/fail signal on its own: an empty block list on a mature tenant may simply mean no incident has required one yet, so it is reported as a soft note rather than a finding that changes the check's Result.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | `SecurityTeamAllowBlockListDelegation` is `Enabled` - SecOps can block from the portal during an incident |
| Warning | `SecurityTeamAllowBlockListDelegation` is `Disabled` (or missing/unexpected), or the tenant federation configuration could not be retrieved - this is a response-readiness gap, not a hard security Fail |
| Fail | Both `Get-CsTenantFederationConfiguration` and `Get-CsTeamsExternalAccessConfiguration` fail to retrieve data |

The current blocked-users count/listing from `Get-CsTeamsExternalAccessConfiguration` is appended to the Finding as informational context and never independently changes the Result.

## Recommendation

Run `Set-CsTenantFederationConfiguration -SecurityTeamAllowBlockListDelegation Enabled` to grant the security team the ability to block malicious external domains and users directly from the Defender security portal during an active incident, without requiring a hand-off to someone with PowerShell access.

## Reference

- [Set-CsTenantFederationConfiguration](https://learn.microsoft.com/en-us/powershell/module/microsoftteams/set-cstenantfederationconfiguration)
