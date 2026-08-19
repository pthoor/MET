# MET-Teams004 - ZAP for Teams

**Category:** Teams | **Severity:** High

## What it checks

Reviews the tenant's Teams protection policy via `Get-TeamsProtectionPolicy` and `Get-TeamsProtectionPolicyRule`:

- **`ZapEnabled`** - whether zero-hour auto purge is active for Teams chats. Unlike email ZAP, this is a single tenant-wide policy rather than a per-recipient effective-coverage model - Teams protection does not support multiple named policies the way anti-spam/anti-malware do
- **Quarantine tag permissions** - whether `MalwareQuarantineTag` and `HighConfidencePhishQuarantineTag` point to `AdminOnlyAccessPolicy` (or, when they point elsewhere, whether that quarantine policy's `EndUserQuarantinePermissions.PermissionToRelease` is `$false`); an unset tag or a tag that permits self-release means a user could release a message ZAP already determined was malicious/high-confidence phish
- **Rule exceptions** - enabled `TeamsProtectionPolicyRule` entries with `ExceptIfSentTo`/`ExceptIfSentToMemberOf`/`ExceptIfRecipientDomainIs` conditions, which narrow effective ZAP coverage below what the policy's `ZapEnabled` flag alone would suggest. Exceptions on a *disabled* rule are ignored since they have no effect

## Why it matters

ZAP retroactively removes messages already delivered once Defender for Office 365's cloud detection catches up - useful because detection engines improve continuously and a message judged clean at delivery time can be reclassified minutes or hours later. Without ZAP for Teams, a malicious link or file shared in a Teams chat stays visible and clickable indefinitely after the fact, even though the equivalent email would have been purged. The quarantine-tag checks close a related but separate gap: ZAP moving a message to quarantine is meaningless as a control if the assigned quarantine policy then lets the recipient release it themselves, undoing the ZAP action. Rule exceptions matter because a tenant-wide `ZapEnabled = $true` can still leave specific recipients, groups, or domains silently uncovered if a policy rule excepts them - the aggregate flag alone does not guarantee blanket coverage.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | `ZapEnabled` is `$true`, both quarantine tags are `AdminOnlyAccessPolicy` (or resolve to a policy with `PermissionToRelease = $false`), and no enabled rule has exceptions |
| Fail | `ZapEnabled` is `$false`, either quarantine tag is unset or allows self-release, or the Teams protection policy could not be retrieved / does not exist |
| Warning | ZAP and quarantine permissions are otherwise compliant, but one or more enabled `TeamsProtectionPolicyRule` entries except specific recipients/groups/domains from coverage |

## Recommendation

```powershell
Set-TeamsProtectionPolicy -ZapEnabled $true
```

Ensure `MalwareQuarantineTag` and `HighConfidencePhishQuarantineTag` on the Teams protection policy use `AdminOnlyAccessPolicy`, or a custom quarantine policy with `PermissionToRelease` disabled. Review any `TeamsProtectionPolicyRule` exceptions and remove ones that are not deliberate - excepted recipients receive no retroactive removal of malicious Teams messages. If no Teams protection policy exists yet, configure it in the Microsoft Defender portal at `security.microsoft.com/securitysettings/teamsProtectionPolicy` (requires Defender for Office 365 Plan 1 or Plan 2).

## Reference

- [Zero-hour auto purge for Microsoft Teams](https://learn.microsoft.com/en-us/defender-office-365/zero-hour-auto-purge)
