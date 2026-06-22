# MET-MDO002 — Safe Attachments

**Category:** MDO | **Severity:** High

## What it checks

Verifies that Safe Attachments policies are enabled and that the action is not `Allow`:

- `Enable` — policy is active
- `Action` — must be `Block` or `DynamicDelivery` (not `Allow`)

## Why it matters

Safe Attachments detonates email attachments in a sandbox before they reach the user's inbox. An `Allow` action means the policy is in place but provides no protection — attachments are delivered without scanning. `DynamicDelivery` is preferred in most environments because it delivers the message body immediately while attachments are scanned, reducing user delay.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | Policy enabled with `Block` or `DynamicDelivery` |
| Fail | Policy disabled, action is `Allow`, or no policies exist |

## Recommendation

Set action to `DynamicDelivery` for best user experience, or `Block` for maximum strictness. Never use `Allow` on an active policy.

## Reference

- [Safe Attachments in Microsoft Defender for Office 365](https://aka.ms/mdo-safeattachments)
