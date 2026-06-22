# MET-MDO006 — Anti-Spam Inbound

**Category:** MDO | **Severity:** Medium

## What it checks

Verifies inbound anti-spam (hosted content filter) policy settings:

- `SpamAction` — action for spam (`MoveToJmf` or `Quarantine`, not `AddXHeader`/`NoAction`)
- `HighConfidenceSpamAction` — action for high-confidence spam (`MoveToJmf` or `Quarantine`)
- `PhishSpamAction` — action for phishing (`MoveToJmf` or `Quarantine`)
- `HighConfidencePhishAction` — must be `Quarantine`
- `BulkThreshold` (BCL) — 6 or lower recommended

## Why it matters

Weak spam actions mean malicious mail reaches users' inboxes rather than being quarantined. High-confidence phish should always be quarantined rather than moved to junk — users are more likely to act on mail in the inbox. A BCL threshold above 6 allows more bulk commercial mail through.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | All thresholds and actions at recommended values |
| Fail | Any action is `NoAction` or `AddXHeader`, high-confidence phish not quarantined, or BCL > 6 |

## Reference

- [Configure spam filter policies](https://aka.ms/mdo-antispam)
