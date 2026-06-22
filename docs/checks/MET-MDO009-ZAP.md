# MET-MDO009 — Zero-Hour Auto Purge (ZAP)

**Category:** MDO | **Severity:** High

## What it checks

Verifies that ZAP is enabled in all inbound anti-spam policies:

- `ZapEnabled` — global ZAP toggle
- `SpamZapEnabled` — ZAP for spam
- `PhishZapEnabled` — ZAP for phishing

## Why it matters

ZAP retroactively removes messages from delivered inboxes when a verdict changes post-delivery. This is critical for zero-day attacks: a message that was clean at delivery time may be re-classified within hours. Without ZAP, those messages remain in user inboxes indefinitely.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | All three ZAP settings enabled |
| Fail | Any ZAP setting disabled |

## Recommendation

Ensure ZAP is enabled globally and for both spam and phishing in every active anti-spam policy.

## Reference

- [Zero-hour auto purge (ZAP) in Microsoft Defender for Office 365](https://aka.ms/mdo-zap)
