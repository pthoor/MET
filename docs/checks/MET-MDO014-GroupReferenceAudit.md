# MET-MDO014 - Group Reference Audit

**Category:** MDO | **Severity:** High (empty group) / Informational (populated group)

## What it checks

Scans every **enabled** EOP and MDO preset and custom rule (EOP Preset, MDO Preset, Safe Links, Safe Attachments, Anti-Phishing, Anti-Spam) for group-based recipient conditions (`SentToMemberOf` / `ExceptIfSentToMemberOf`). For each unique group referenced, it resolves the group's current member count via Microsoft Graph (falling back to Exchange Online's `Get-DistributionGroupMember` / `Get-UnifiedGroupLinks` when Graph is unavailable) and reports one result per group.

## Why it matters

A policy that targets `SentToMemberOf: "VIP Executives"` looks correctly configured in the admin center - it shows `Enabled`, has a sensible `Priority`, and lists a real group name. But if that group has quietly emptied out (an offboarding script removed everyone, a rename broke the original membership, or it was created and never populated), the policy silently protects nobody. Nothing in the Defender portal flags this - the rule still shows as active and correctly targeted. This check makes group membership a visible, auditable number instead of an assumption.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Info | The referenced group has one or more members - shown with its member count and which rule(s) reference it |
| Fail | The referenced group has 0 members - the policy condition matches nobody |
| Fail | Rule or group-membership data could not be retrieved |
| NotApplicable | No mailboxes exist in the tenant, or no enabled rule uses a group-based recipient condition |

## Recommendation

For each empty group reported:

1. Confirm the group still exists and is the one the admin intended - a typo'd or renamed group identity resolves to 0 members the same way an actually-empty group does.
2. Repopulate the group, or remove the stale `SentToMemberOf`/`ExceptIfSentToMemberOf` reference from the rule(s) listed if the group is intentionally retired.
3. For every populated group listed at Info level, treat the member count as a point-in-time snapshot worth re-checking periodically - group membership drifts as people join, leave, or change teams, and MET does not track membership trend over time.

## Reference

- [Recommended settings for EOP and Microsoft Defender for Office 365 security](https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365)
- [Get-DistributionGroupMember](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-distributiongroupmember)
