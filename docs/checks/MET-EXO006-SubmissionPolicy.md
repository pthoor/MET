# MET-EXO006 — Submission Policy

**Category:** EXO | **Severity:** Medium

## What it checks

Verifies the report submission policy configuration:

- `EnableReportToMicrosoft` — user-reported messages are also submitted to Microsoft for analysis
- `EnableUserEmailNotification` — users are notified of the review outcome
- A custom submission mailbox (via `Get-ReportSubmissionRule`) is configured so SecOps receives copies

## Why it matters

User-reported messages are one of the highest-signal sources of threat intelligence. Forwarding them to Microsoft improves global protection for all tenants. Routing them to a SecOps mailbox enables local investigation and response. Without a submission mailbox, SecOps has no visibility into what users are flagging as suspicious.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | Reporting to Microsoft on, notification on, custom mailbox configured |
| Fail | Reporting to Microsoft disabled |
| Warning | Reporting enabled but no custom mailbox or notifications off |

## Recommendation

Enable `EnableReportToMicrosoft`. Configure a dedicated SecOps mailbox as the submission target. Enable user notifications so reporters receive feedback and are reinforced in the reporting behaviour.

## Reference

- [User-reported message settings in EOP and Defender for Office 365](https://aka.ms/mdo-submissionpolicy)
