# MET-EXO009 - Quarantine Policy Verdict Alignment

**Category:** EXO | **Severity:** High

## What it checks

Cross-references every filter policy that can route a message to quarantine - `Get-HostedContentFilterPolicy` (anti-spam), `Get-MalwareFilterPolicy` (anti-malware), `Get-AntiPhishPolicy` (impersonation/spoof, MDO Plan 1+), and `Get-SafeAttachmentPolicy` (MDO Plan 1+, `Block` action only) - against the quarantine policy each verdict is assigned to, and checks whether that quarantine policy's `PermissionToRelease` bit allows the end user to self-release the message.

Per Microsoft's own published Default/Standard/Strict quarantine-policy matrix (verified against [Recommended email and collaboration threat policy settings](https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365)), only **two** verdicts have an actual restrictive floor - a case where Microsoft's own Strict preset uses `AdminOnlyAccessPolicy` (no self-release):

- **Malware**
- **High-Confidence Phish**

Every other verdict this check could theoretically evaluate - Phish, Mailbox Intelligence Phish, Spoof, Impersonated User, Impersonated Domain, High-Confidence Spam, Spam, Bulk - uses a **full-access** quarantine policy in Microsoft's own Strict preset. There is no restrictive floor to enforce for any of them, so this check does not evaluate them at all.

Safe Attachments' Malware/Phish verdict (Block action) is bucketed into the `Malware` verdict for evaluation purposes, matching the matrix (Safe Attachments malware/phish is also `AdminOnlyAccessPolicy` under Standard and Strict).

**Preset-generated source policies are skipped entirely.** Any `HostedContentFilterPolicy`, `MalwareFilterPolicy`, `AntiPhishPolicy`, or `SafeAttachmentPolicy` whose `Name` matches `^(Strict|Standard) Preset Security Policy` (via `Test-METIsPresetSecurityPolicyName`) is excluded from evaluation - its quarantine tag assignments are Microsoft-managed, guaranteed correct by construction, and not admin-actionable. Evaluating them would only ever produce a non-actionable finding.

The Fail condition reads the quarantine policy's actual `PermissionToRelease` bit, not the tag's name - so a custom quarantine policy that independently implements "no access" for Malware still Passes, and a custom policy pointing Malware at any full-access tag (built-in or custom) still Fails.

## Why it matters

If a custom (admin-created) quarantine policy is mistakenly assigned to the Malware or High-Confidence Phish verdict with self-release permission enabled, a user could release a message containing malware or a high-confidence phishing lure directly into their own mailbox with no admin review - defeating the purpose of quarantining it in the first place. This is the one place in the quarantine pipeline where Microsoft itself enforces a hard floor (`AdminOnlyAccessPolicy`) under both Standard and Strict presets, so any custom configuration that weakens it for these two verdicts is a genuine, actionable gap.

Earlier versions of this check also treated impersonation (`Impersonated User`/`Impersonated Domain`) as high-risk (Fail) and Phish/Mailbox Intelligence Phish/Spoof as medium-risk (Warning) if self-release was allowed. That contradicted Microsoft's own Strict preset, which uses full-access quarantine policies for all five of those verdicts - so the older logic flagged Microsoft's own recommended configuration as a misconfiguration on any tenant with Standard or Strict assigned to anyone. This was corrected in the 2026-08 quarantine-policy accuracy pass.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | Every non-preset policy's Malware and High-Confidence Phish verdict tags resolve to a quarantine policy with `PermissionToRelease = $false` (or no such assignment exists) |
| Fail | A non-preset policy assigns Malware or High-Confidence Phish to a quarantine tag with `PermissionToRelease = $true`, or to a tag that does not exist; or filter policies could not be retrieved at all |

There is no Warning tier - the removed Medium-risk tier (Phish/Mailbox Intelligence Phish/Spoof) had no basis in Microsoft's own preset design and was dropped along with the incorrect High-risk classification of impersonation.

## Recommendation

For Malware and High-Confidence Phish verdicts, assign a quarantine policy with `PermissionToRelease` disabled - use the built-in `AdminOnlyAccessPolicy` or a custom policy with equivalent restrictions. No action is needed for any other verdict type; Microsoft's own Strict preset uses full-access quarantine policies for Phish, Mailbox Intelligence Phish, Spoof, and both impersonation verdicts, so there is nothing to remediate there.

## Reference

- [Quarantine policies in Microsoft Defender for Office 365](https://aka.ms/mdo-quarantinepolicies)
- [Recommended email and collaboration threat policy settings](https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365)
