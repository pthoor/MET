# MET-MDO002 - Safe Attachments

**Category:** MDO | **Severity:** High

## What it checks

Verifies that Safe Attachments policies are enabled and that the action is not `Allow`, and separately reports the tenant-wide toggle that extends Safe Attachments beyond email:

- `Enable` - policy is active
- `Action` - must be `Block` or `DynamicDelivery` (not `Allow`)
- `EnableATPForSPOTeamsODB` (`Get-AtpPolicyForO365`) - Safe Attachments protection for SharePoint, OneDrive and Microsoft Teams file sharing

The global toggle is always reported, including when it is correctly enabled. It is a separate control plane from the per-policy email settings, so a failure to read it is surfaced as its own result rather than leaving the report looking like a complete Safe Attachments assessment.

## Why it matters

Safe Attachments detonates email attachments in a sandbox before they reach the user's inbox. An `Allow` action means the policy is in place but provides no protection - attachments are delivered without scanning. `DynamicDelivery` is preferred in most environments because it delivers the message body immediately while attachments are scanned, reducing user delay.

## Pass / Fail / Warning

Per Safe Attachments policy:

| Result | Condition |
|---|---|
| Pass | Policy enabled with `Block` or `DynamicDelivery` |
| Fail | Policy disabled, action is `Allow`, or no policies exist |

For the global SharePoint / OneDrive / Teams setting:

| Result | Condition |
|---|---|
| Pass | `EnableATPForSPOTeamsODB` is `$true` |
| Fail | `EnableATPForSPOTeamsODB` is `$false` |
| Warning | `Get-AtpPolicyForO365` could not be read - the setting was not established; the failure is carried in `Error` |
| NotApplicable | The policy returned no `EnableATPForSPOTeamsODB` property - the setting was not established; recorded in `Error` |

## Recommendation

Set action to `DynamicDelivery` for best user experience, or `Block` for maximum strictness. Never use `Allow` on an active policy.

## Reference

- [Safe Attachments in Microsoft Defender for Office 365](https://aka.ms/mdo-safeattachments)
