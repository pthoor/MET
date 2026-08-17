# MET-MDO014 - Group Reference Audit

**Category:** MDO | **Severity:** High (empty group) / Medium (group could not be resolved) / Informational (populated group)

## What it checks

Scans every **enabled** EOP and MDO preset and custom rule (EOP Preset, MDO Preset, Safe Links, Safe Attachments, Anti-Phishing, Anti-Spam) for group-based recipient conditions (`SentToMemberOf` / `ExceptIfSentToMemberOf`). For each unique group referenced, it resolves the group's current member count via Microsoft Graph (falling back to Exchange Online's `Get-DistributionGroupMember` / `Get-UnifiedGroupLinks` when Graph is unavailable) and reports one result per group.

## Why it matters

A policy that targets `SentToMemberOf: "VIP Executives"` looks correctly configured in the admin center - it shows `Enabled`, has a sensible `Priority`, and lists a real group name. But if that group has quietly emptied out (an offboarding script removed everyone, a rename broke the original membership, or it was created and never populated), the policy silently protects nobody. Nothing in the Defender portal flags this - the rule still shows as active and correctly targeted. This check makes group membership a visible, auditable number instead of an assumption.

## Pass / Fail / Warning

| Result | Severity | Condition |
|---|---|---|
| Info | Informational | The referenced group resolved successfully and has one or more members - shown with its member count and which rule(s) reference it |
| Fail | High | The referenced group resolved successfully but has **0 members** - the policy condition matches nobody |
| Fail | Medium | The referenced group **could not be resolved at all** (Graph, `Get-DistributionGroupMember`, and `Get-UnifiedGroupLinks` all failed), so its coverage is unknown. Reported per group, with the underlying errors in the `Error` field - explicitly *not* reported as an empty group |
| Fail | Medium | One or more **nested** groups could not be expanded while their parent resolved, so the reported member counts may be incomplete. Emitted once, only for errors not already attributed to a specific group above |
| Fail | High | Rule collections (`Get-SafeLinksRule`, `Get-AntiPhishRule`, …) or the mailbox list could not be retrieved, so the audit could not run at all |
| NotApplicable | Medium | No mailboxes exist in the tenant, or no enabled rule uses a group-based recipient condition |

A group is never reported twice for the same underlying cause: a resolution failure produces the per-group Medium `Fail` **or** contributes to the trailing nested-expansion summary, never both.

## Recommendation

For each empty group reported:

1. Confirm the group still exists and is the one the admin intended - a typo'd or renamed group identity resolves to 0 members the same way an actually-empty group does.
2. Repopulate the group, or remove the stale `SentToMemberOf`/`ExceptIfSentToMemberOf` reference from the rule(s) listed if the group is intentionally retired.
3. For each group reported as unresolvable, check that the identity in the rule still exists and that the running account has Exchange View-Only Recipients and (if installed) Microsoft Graph `Group.Read.All` - an unresolvable group is an unknown, not a confirmed gap.
4. For every populated group listed at Info level, treat the member count as a point-in-time snapshot worth re-checking periodically - group membership drifts as people join, leave, or change teams, and MET does not track membership trend over time.

## Reference

- [Recommended settings for EOP and Microsoft Defender for Office 365 security](https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365)
- [Get-DistributionGroupMember](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-distributiongroupmember)
