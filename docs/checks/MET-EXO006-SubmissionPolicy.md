# MET-EXO006 - Submission Policy

**Category:** EXO | **Severity:** High

## What it checks

MET retrieves `Get-ReportSubmissionPolicy` and, when available, its associated `Get-ReportSubmissionRule`. It emits separate results for the report-button mode and Microsoft feedback loop, SecOps mailbox routing, post-review user notifications, and rule/policy mailbox-address consistency. A failure to retrieve the submission rule is recorded only as verbose output; the policy result families continue with no resolved custom mailbox.

The report-button mode is derived from `EnableReportToMicrosoft`, `EnableThirdPartyAddress`, and whether any of the Junk, Not Junk, or Phishing flows is sent to a customized address. Those three custom-mailbox flows are independently represented by `ReportJunkToCustomizedAddress`, `ReportNotJunkToCustomizedAddress`, and `ReportPhishToCustomizedAddress`.

## Why it matters

User-reported messages provide a high-signal input for local investigation and Microsoft threat analysis. Sending reports to Microsoft makes them visible on the Defender Submissions page and contributes to the feedback loop; routing them to a SecOps mailbox gives the security team a direct operational copy. Notifications show users that reports were reviewed, and consistent rule and policy addresses prevent individual report types silently going to a different mailbox.

## Results

### Base policy retrieval

| Result | Severity | Condition |
|---|---|---|
| Fail | Medium | `Get-ReportSubmissionPolicy` throws. The result includes the error detail. |
| Fail | Medium | `Get-ReportSubmissionPolicy` returns no policy. |

Neither base failure emits the four named result families below.

### User Reported Message Settings - Report Button

| Result | Severity | Condition |
|---|---|---|
| Fail | High | Reporting is completely disabled: no reports go to Microsoft, no non-Microsoft add-in is configured, and no Junk, Not Junk, or Phishing flow goes to a custom mailbox. |
| Fail | High | One or both reporting-mode properties are absent or `$null` and no reporting flow is observed; the report-button mode and destinations cannot be established. The result identifies the absent property or properties and includes an error message. |
| Fail | High | A non-Microsoft add-in is configured but `EnableReportToMicrosoft` is disabled. Reports are not visible on the Defender Submissions page and Microsoft receives no feedback. |
| Fail | High | The built-in Outlook reporting path sends one or more report flows to a custom mailbox, but `EnableReportToMicrosoft` is disabled. Microsoft performs no analysis and the Defender Submissions page is empty. |
| Warning | Medium | A non-Microsoft add-in is configured and reports are forwarded to Microsoft. The add-in and preservation of message metadata need verification. |
| NotApplicable | High | `EnableReportToMicrosoft` is confirmed `$true`, but `EnableThirdPartyAddress` is absent or `$null`; MET cannot establish whether the Microsoft built-in button or a non-Microsoft add-in is in use. The result includes an error message. |
| Pass | High | The built-in Microsoft report button is active and reports are sent to Microsoft for analysis. |

### User Reported Message Settings - SecOps Mailbox

This family is emitted only when reporting is not completely disabled.

| Result | Severity | Condition |
|---|---|---|
| Warning | Medium | No custom mailbox is configured: either no Junk, Not Junk, or Phishing flow is enabled for a custom address, or no rule `SentTo` mailbox could be resolved. |
| Warning | Low | A custom mailbox is resolved, but one or more of the Junk, Not Junk, and Phishing flows is not routed to it. The finding identifies the missing flow or flows. |
| Pass | Medium | All three custom-mailbox flows—Junk, Not Junk, and Phishing—are enabled, and a submission-rule mailbox is resolved. Address agreement is evaluated separately by the Mailbox Address Consistency family. |

If the rule contains multiple recipients, MET uses the first `SentTo` address for these comparisons and reports the additional recipients as a note.

### User Reported Message Settings - User Notifications

This family is emitted only when reporting is not completely disabled and reports are sent to Microsoft.

| Result | Severity | Condition |
|---|---|---|
| Warning | Low | `EnableUserEmailNotification` is not enabled; users receive no post-review feedback. |
| Pass | Low | `EnableUserEmailNotification` is enabled; users are notified after review. |

### User Reported Message Settings - Mailbox Address Consistency

This family is emitted only when reporting is not completely disabled and a submission-rule mailbox is resolved. For each custom flow in use—Junk, Not Junk, Phishing, and, when a non-Microsoft add-in is configured, the third-party address—MET compares the rule mailbox with the first policy address only when the corresponding address property is populated. Missing or empty address properties are skipped rather than treated as mismatches.

| Result | Severity | Condition |
|---|---|---|
| Warning | Low | At least one applicable policy address differs from the submission rule's `SentTo` mailbox. |
| Pass | Low | No mismatch was found among the populated policy address properties. Because missing or empty address properties are skipped, Pass does not establish that every active report type was compared. |

## Recommendation

In the Defender portal, go to **Settings > Email & collaboration > User reported settings**. Prefer the built-in Microsoft report button, enable **Send reported messages to Microsoft**, route Junk, Not Junk, and Phishing to a dedicated SecOps mailbox, and enable post-review user notifications. Keep `Set-ReportSubmissionRule` and the matching `Set-ReportSubmissionPolicy` `*Addresses` values aligned.

## Reference

- [User-reported message settings in EOP and Defender for Office 365](https://aka.ms/mdo-user-reported-settings)
- [Set-ReportSubmissionPolicy](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-reportsubmissionpolicy)
