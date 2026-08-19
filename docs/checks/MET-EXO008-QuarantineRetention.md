# MET-EXO008 - Quarantine Retention

**Category:** EXO | **Severity:** Low

## What it checks

For each enabled `HostedContentFilterPolicy` (anti-spam policy) - the tenant default plus any custom policy with an enabled assigning rule - `QuarantineRetentionPeriod` is evaluated against a 30-day baseline, with the evaluation and recommendation branching on whether the policy is Microsoft-managed or admin-managed:

- **Default and custom policies** - flagged Fail if retention is below 30 days, with an actionable `Set-HostedContentFilterPolicy` recommendation to raise it. Pass at 30 days or above.
- **Standard/Strict preset security policies** (`Strict Preset Security Policy...` / `Standard Preset Security Policy...`, detected via `Test-METIsPresetSecurityPolicyName`) - never flagged Fail. Preset-generated policies are Microsoft-managed and their retention is fixed at 30 days by design; `Set-HostedContentFilterPolicy` errors if run against one. A preset policy at 30 days or above Passes, noting the value is fixed and not admin-configurable. The defensive case - a preset policy somehow reporting retention below 30 days - is reported as a Warning describing it as an unexpected condition to investigate (e.g. with Microsoft support), not an admin action item, since there is no supported command to change it.

## Why it matters

`QuarantineRetentionPeriod` controls how long a quarantined message stays available for an end user or admin to review and release before it is permanently purged. Too short a window turns an over-aggressive spam/phish verdict into a silent, unrecoverable data-loss event - the message is gone before anyone notices it was misclassified. Microsoft's own Standard and Strict preset security policies fix this at 30 days; MET applies the same 30-day bar to Default and custom anti-spam policies so hand-rolled configurations don't fall short of Microsoft's own recommended baseline.

### This same value governs anti-phishing quarantine too

`QuarantineRetentionPeriod` on the anti-spam policy is not scoped to spam/malware verdicts only - it also controls retention for anti-phishing quarantine actions (spoof intelligence, user/domain impersonation) for the same recipient. Microsoft's documentation is explicit: *"This retention period is also controlled by the [quarantine retention] setting in anti-spam policies. The retention period is the value from the first matching anti-spam policy that the recipient is defined in."* There is no separate anti-phish retention knob to configure - admins searching for one won't find it, because this check (and this one setting) already covers it.

### What's out of scope, and why

Retention for other quarantine verdicts is fixed tenant-wide and not admin-configurable, so there is nothing to check:

- **Malware** (anti-malware policy verdicts) - fixed at 30 days
- **Safe Attachments** (malware/phish and encrypted/unscannable attachment verdicts) - fixed at 30 days
- **ZAP for Teams** (Teams Protection Policy malware/high-confidence-phish verdicts) - fixed at 30 days

None of these expose a retention parameter on their respective `Set-*` cmdlets, unlike `Set-HostedContentFilterPolicy -QuarantineRetentionPeriod`, so there is no admin lever to assess.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | Retention ≥ 30 days - for a Default/custom policy, an admin-tunable value at or above the recommended baseline; for a preset policy, the Microsoft-fixed value confirmed as expected |
| Fail | Default or custom policy with retention < 30 days - admin-actionable via `Set-HostedContentFilterPolicy` |
| Warning | A preset policy unexpectedly reporting retention < 30 days - not admin-actionable (the command would error against a preset), flagged for investigation as a Microsoft-side anomaly instead |

## Recommendation

For Default or custom policies below 30 days, run:

```powershell
Set-HostedContentFilterPolicy -Identity '<PolicyName>' -QuarantineRetentionPeriod 30
```

For Standard/Strict preset security policies, no action is available or needed - retention is fixed at 30 days by Microsoft. If a preset policy is ever observed below 30 days, treat it as a service anomaly (e.g. open a support request) rather than attempting to remediate it with `Set-HostedContentFilterPolicy`.

## Reference

- [Quarantined email messages - quarantine retention](https://learn.microsoft.com/en-us/defender-office-365/quarantine-about#quarantine-retention)
- [Preset security policies](https://learn.microsoft.com/en-us/defender-office-365/preset-security-policies)
