# MET-Teams005 - Teams User Reporting

**Category:** Teams | **Severity:** Medium

## What it checks

Reviews two independent controls that together determine whether a suspicious message reported by a user *inside a Teams chat* actually reaches the security team:

- **Defender portal - report submission policy** (`Get-ReportSubmissionPolicy`) - `ReportChatMessageEnabled` controls whether Teams chat reports are monitored by Defender for Office 365 at all; `ReportChatMessageToCustomizedAddressEnabled` (checked only when the former is enabled) controls whether those reports are also copied to a SecOps mailbox for direct inbox visibility, rather than only appearing inside the Defender portal's submissions queue
- **Teams admin center - messaging policy** (`Get-CsTeamsMessagingPolicy`) - `AllowSecurityEndUserReporting` controls whether the "Report a security concern" button is even present in the Teams client for users assigned that policy. Checked across every messaging policy, not just `Global`, since a per-user/group policy assignment can silently suppress the button for a subset of users even when the tenant default has it enabled

Both halves must be correct for end-to-end reporting to work: the button has to exist for a user to report something, and the report has to actually be routed somewhere the security team monitors.

## Why it matters

Teams increasingly carries the same phishing/vishing/QR-lure traffic email does (see MET-Teams006), but unlike email, most tenants have no mature triage pipeline for user-reported Teams messages - the button and the policy exist, but are frequently left at defaults nobody has reviewed. If `ReportChatMessageEnabled` is off, reports a user submits from Teams are effectively discarded - there's no equivalent of an email reported-messages mailbox catching them downstream. If it's on but not copied to a SecOps mailbox, reports only surface inside the Defender portal's submissions UI, which depends on someone proactively checking it rather than an alert-driven inbox. And if `AllowSecurityEndUserReporting` is disabled in a messaging policy, the affected users have no reporting mechanism at all, regardless of how well the Defender-portal side is configured - the human-detection layer for Teams-based lures is silently missing for exactly the population assigned that policy.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | `ReportChatMessageEnabled` is `$true`, `ReportChatMessageToCustomizedAddressEnabled` is `$true`, and every Teams messaging policy has `AllowSecurityEndUserReporting` enabled (or unset) |
| Fail | `ReportChatMessageEnabled` is `$false`; `ReportChatMessageEnabled` is `$true` but `ReportChatMessageToCustomizedAddressEnabled` is `$false`; one or more messaging policies explicitly set `AllowSecurityEndUserReporting` to `$false`; or the report submission policy could not be retrieved |

## Recommendation

1. In the Defender portal, go to **Settings > Email & collaboration > User reported settings** and enable **"Monitor reported items in Microsoft Teams"**, routing Teams reports to your SecOps mailbox alongside email reports.
2. In the Teams admin center (`admin.teams.microsoft.com`), ensure **"Report a security concern"** is enabled in every active messaging policy, not just Global.

## Reference

- [User reported settings](https://learn.microsoft.com/en-us/defender-office-365/submissions-user-reported-messages-custom-mailbox)
