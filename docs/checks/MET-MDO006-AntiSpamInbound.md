# MET-MDO006 - Anti-Spam Inbound

**Category:** MDO | **Severity:** Medium

## What it checks

Resolves the effective inbound anti-spam policy for each assessable mailbox using preset precedence, custom rule priority, user/group/domain conditions, exceptions, and default fallback. It then verifies:

- `SpamAction` - action for spam (`MoveToJmf` or `Quarantine`, not `AddXHeader`/`NoAction`)
- `HighConfidenceSpamAction` - must be `Quarantine` for the Standard baseline
- `PhishSpamAction` - must be `Quarantine` for the Standard baseline
- `HighConfidencePhishAction` - must be `Quarantine`
- `BulkThreshold` (BCL) - 6 or lower recommended
- high-confidence phishing quarantine policy - recommended `AdminOnlyAccessPolicy`
- sender and sender-domain allow entries - reported as unsafe bypasses

Users cannot self-release high-confidence phishing regardless of the selected quarantine policy. A policy that grants release capability permits a release request, not direct release.

Spam and phishing ZAP are assessed separately by MET-MDO009 using the same effective-policy assignments.

The report highlights policy overlap and warns when a higher-priority custom catch-all shadows specialized policies. Where fallback coverage is below baseline, it recommends either expanding preset coverage or placing a compliant custom catch-all after specialized custom policies.

## Why it matters

Weak spam actions mean malicious mail reaches users' inboxes rather than being quarantined. High-confidence phish should always be quarantined rather than moved to junk - users are more likely to act on mail in the inbox. A BCL threshold above 6 allows more bulk commercial mail through.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | Every mailbox receives an effective policy that meets the Standard baseline |
| Fail | One or more mailboxes receive an effective policy below baseline |
| Warning | Effective coverage is incomplete because data could not be retrieved |
| NotApplicable | No assessable mailboxes were found |

## Reference

- [Configure spam filter policies](https://aka.ms/mdo-antispam)
- [Microsoft recommended threat policy settings](https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365#anti-spam-policy-settings)
