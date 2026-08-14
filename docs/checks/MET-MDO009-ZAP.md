# MET-MDO009 - Zero-Hour Auto Purge (ZAP)

**Category:** MDO | **Severity:** High

## What it checks

Resolves the effective inbound anti-spam policy for every assessable mailbox, then verifies:

- `SpamZapEnabled` - ZAP for spam
- `PhishZapEnabled` - ZAP for phishing

Ordering observations use the same inbound anti-spam policy resolution as MET-MDO006, including warnings for a catch-all that precedes and shadows specialized custom policies.

## Why it matters

ZAP retroactively removes messages from delivered inboxes when a verdict changes post-delivery. This is critical for zero-day attacks: a message that was clean at delivery time may be re-classified within hours. Without ZAP, those messages remain in user inboxes indefinitely.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | Spam and phishing ZAP are enabled for every mailbox's effective policy |
| Fail | Spam or phishing ZAP is disabled for one or more effectively covered mailboxes |
| Warning | Effective coverage is incomplete because data could not be retrieved |
| NotApplicable | No assessable mailboxes were found |

## Recommendation

Enable ZAP for spam and phishing in the effective inbound anti-spam policy for every affected recipient. Unused and shadowed policies do not change the tenant result.

## Reference

- [Zero-hour auto purge (ZAP) in Microsoft Defender for Office 365](https://aka.ms/mdo-zap)
