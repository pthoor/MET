# MET-EXO017 - Quarantine Notification Cadence

**Category:** EXO | **Severity:** Informational

## What it checks

Reviews the tenant-wide cadence at which quarantine notification emails are sent to end users, for any quarantine policy that has notifications enabled (`ESNEnabled = $true`).

- **Current cadence** - reports the configured `EndUserSpamNotificationFrequency` value (4 hours, 1 day, or 7 days)
- **Retrieval health** - confirms the global quarantine policy object can be read

## Why it matters

`EndUserSpamNotificationFrequency` is a single tenant-wide setting (not per-policy) read from the built-in global quarantine policy object (`Get-QuarantinePolicy -QuarantinePolicyType GlobalQuarantinePolicy`, identity `DefaultGlobalTag`). It controls how often Microsoft 365 sends end users a summary email of messages sitting in quarantine, for every quarantine policy across the tenant that has end-user notifications turned on.

This is a timeliness/user-experience trade-off, not a security control:

- A **faster** cadence (4 hours) gives users more prompt awareness that a legitimate email was misclassified into quarantine, reducing the time a real business email sits unseen.
- A **slower** cadence (1 day or 7 days) means fewer interruption emails, at the cost of a longer window before a user notices a misclassified message.

Microsoft does not publish a recommended value for this setting - the right cadence depends on organizational tolerance for interruption versus responsiveness to false positives. MET surfaces the current value so it can be a deliberate choice reviewed periodically, rather than an unexamined default.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Info | Cadence successfully retrieved and recognized (4 hours / 1 day / 7 days), or retrieved but not a recognized value |
| Fail | Unable to retrieve global quarantine notification settings (access issue or cmdlet failure) |

Note: This check returns `Info` in all successful cases, including when the value can't be mapped to one of the three known cadences - there is no "correct" cadence for MET to assert Pass/Fail against, only a setting worth reviewing.

## Recommendation

Review the global quarantine notification cadence periodically:

1. Confirm the current cadence matches your organization's preference for interruption frequency versus prompt awareness of misclassified mail
2. To change it, run: `Get-QuarantinePolicy -QuarantinePolicyType GlobalQuarantinePolicy | Set-QuarantinePolicy -EndUserSpamNotificationFrequency <04:00:00|1.00:00:00|7.00:00:00>`
3. This setting only affects quarantine policies that already have end-user notifications enabled (`ESNEnabled = $true`) - it has no effect where notifications are off entirely

## Reference

- [Quarantine policies - Configure global quarantine notification settings](https://learn.microsoft.com/en-us/defender-office-365/quarantine-policies#configure-global-quarantine-notification-settings-in-the-microsoft-defender-portal)
- [Quarantined email messages in EOP and Microsoft Defender for Office 365](https://learn.microsoft.com/en-us/defender-office-365/quarantine-about)
