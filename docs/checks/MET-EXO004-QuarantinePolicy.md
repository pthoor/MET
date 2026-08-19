# MET-EXO004 - Quarantine Policies

**Category:** EXO | **Severity:** Medium

## What it checks

Excludes the 4 Microsoft built-in, unmodifiable quarantine policies (`AdminOnlyAccessPolicy`, `DefaultFullAccessPolicy`, `DefaultFullAccessWithNotificationPolicy`, `NotificationEnabledPolicy` - detected via `Test-METIsBuiltInQuarantinePolicyName`) and evaluates only genuinely **custom** quarantine policies for one specific, narrow condition:

- `ESNEnabled -eq $false` **and** `EndUserQuarantinePermissionsValue -gt 0` - end users have been granted permission to act on quarantined messages (review, release, delete, etc.), but end-user spam notifications (ESN) are disabled, so they are never told anything is quarantined and have no way to know to use that permission.

If a tenant has no custom quarantine policies at all - only the 4 built-ins - the check returns a single Pass; there is nothing to review.

## Why it changed (v0.9.0)

The previous version of this check iterated **every** quarantine policy, including the built-ins, and flagged `EndUserQuarantinePermissionsValue -eq 0` as a Warning ("users cannot review or release quarantined messages"). `AdminOnlyAccessPolicy` - Microsoft's own "No access" policy, present on every tenant and used by design for Malware and High-Confidence Phish verdicts even under the Strict preset - always has that value. This produced a **guaranteed false-positive Warning on every single MET run**, on every tenant, flagging Microsoft's correct-by-design behavior as a misconfiguration.

The old check also read `$policy.QuarantineRetentionDays` and flagged values under 15 days. Per `Set-QuarantinePolicy`'s own documentation, that parameter is "reserved for internal Microsoft use" - real retention lives on the filter policies (anti-spam, anti-malware, etc.), not on the quarantine tag object itself, so this property is non-functional/vestigial for this purpose.

Finally, the old check name-matched policies containing `HighConfidencePhish` or `AdminOnlyAccess` and flagged any end-user self-release permission on them - based on the same wrong assumption. `AdminOnlyAccessPolicy` having no end-user permissions on a high-confidence-phish verdict is correct behavior, not a finding.

All three of the removed conditions are redundant with, and less accurate than, checks that already exist elsewhere:

- **Retention** is correctly evaluated on the filter policy itself by [MET-EXO008](./MET-EXO008-QuarantineRetention.md).
- **Verdict-to-quarantine-tag correctness** (including which verdicts require `PermissionToRelease = $false`) is evaluated per-verdict, preset-aware, by [MET-EXO009](./MET-EXO009-QuarantinePolicyVerdictAlignment.md).

See `docs/gap-analysis-2026-08-quarantine-policies.md` for the full research behind this change, including the canonical Default/Standard/Strict quarantine policy matrix from Microsoft Learn.

## Why it matters

A custom quarantine policy that grants end users permission to act on quarantined mail, but never notifies them that anything is quarantined, is a silent usability gap: the permission exists but is effectively unreachable. Note that `DefaultFullAccessPolicy` itself is "full permissions, no notification" by design - which is exactly why this check only evaluates genuinely custom policies, not the built-ins.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | No custom quarantine policies exist (only built-ins), or a custom policy's notification setting is consistent with its granted permissions |
| Warning | A custom policy grants end-user permissions (`EndUserQuarantinePermissionsValue > 0`) but has `ESNEnabled = $false` |
| Fail | `Get-QuarantinePolicy` could not be retrieved |

## Recommendation

Enable end-user spam notifications (`ESNEnabled`) on any custom quarantine policy that grants end-user permissions, or remove those permissions if notifications are intentionally disabled.

## Reference

- [Quarantine policies in Microsoft Defender for Office 365](https://aka.ms/mdo-quarantinepolicies)
