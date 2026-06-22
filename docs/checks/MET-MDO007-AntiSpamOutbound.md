# MET-MDO007 — Anti-Spam Outbound

**Category:** MDO | **Severity:** Medium

## What it checks

Verifies outbound spam filter policy settings:

- `AutoForwardingMode` — must be `Off` to prevent data exfiltration via auto-forwarding
- `ActionWhenThresholdReached` — should block the sending user, not just alert
- `NotifyOutboundSpamRecipients` — admin notification address is configured

## Why it matters

Auto-forwarding rules are a common post-compromise technique for exfiltrating mail to attacker-controlled addresses. Disabling auto-forwarding at the policy level provides a tenant-wide backstop against compromised accounts silently forwarding all received mail. Outbound spam threshold actions protect the tenant's sending reputation.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | Auto-forward off, block-user action, notification configured |
| Fail | Auto-forwarding not `Off` |
| Warning | Auto-forwarding off but other settings sub-optimal |

## Recommendation

Set `AutoForwardingMode` to `Off`. Set the sending limit action to `BlockUser`. Configure a notification address for SecOps awareness.

## Reference

- [Outbound spam protection in EOP](https://aka.ms/mdo-outboundspam)
