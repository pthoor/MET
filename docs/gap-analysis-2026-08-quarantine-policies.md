# Gap Analysis — 2026-08 — Quarantine Policy Preset/Custom Awareness

Research pass triggered by a design conversation about MET's three existing quarantine checks (EXO004, EXO008, EXO009) not distinguishing Microsoft-managed preset (Standard/Strict) quarantine configuration from admin-managed custom configuration. That conversation surfaced two confirmed, previously-unnoticed false-positive bugs, not just a design gap. Findings verified against Microsoft Learn (checked 2026-08-18): [Quarantine policies](https://learn.microsoft.com/en-us/defender-office-365/quarantine-policies), [Quarantined email messages](https://learn.microsoft.com/en-us/defender-office-365/quarantine-about), [Recommended email and collaboration threat policy settings](https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365), [Preset security policies](https://learn.microsoft.com/en-us/defender-office-365/preset-security-policies), [Set-QuarantinePolicy](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-quarantinepolicy), [Set-SafeAttachmentPolicy](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-safeattachmentpolicy).

Tracked in `ROADMAP.md` under **v0.9.0 — Quarantine policy accuracy pass**.

---

## Core fact: presets are 100% immutable, including which quarantine policy each verdict uses

> "You can't modify the individual threat policies in the preset security protection profiles."
> — [Preset security policies](https://learn.microsoft.com/en-us/defender-office-365/preset-security-policies)

> "Permissions and notification settings in default quarantine policies are read only (aren't modifiable)."
> — [Quarantine policies](https://learn.microsoft.com/en-us/defender-office-365/quarantine-policies#modify-quarantine-policies-in-the-microsoft-defender-portal)

There are exactly 4 built-in, unmodifiable quarantine policies: `AdminOnlyAccessPolicy` (No access, notifications off), `DefaultFullAccessPolicy` (Full access, notifications off), `DefaultFullAccessWithNotificationPolicy` (Full access, notifications on), and `NotificationEnabledPolicy` (legacy tenants only, same as the previous one). Everything else returned by `Get-QuarantinePolicy` is admin-created and genuinely actionable.

### The canonical Default / Standard / Strict matrix

Pulled directly from [Recommended email and collaboration threat policy settings](https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365):

| Threat policy | Verdict | Default | Standard | Strict |
|---|---|---|---|---|
| Anti-malware | Malware | AdminOnlyAccessPolicy | AdminOnlyAccessPolicy | AdminOnlyAccessPolicy |
| Anti-spam | Spam | DefaultFullAccessPolicy¹ | DefaultFullAccessPolicy | DefaultFullAccessWithNotificationPolicy |
| Anti-spam | High confidence spam | DefaultFullAccessPolicy¹ | DefaultFullAccessWithNotificationPolicy | DefaultFullAccessWithNotificationPolicy |
| Anti-spam | Phishing | DefaultFullAccessPolicy¹ | DefaultFullAccessWithNotificationPolicy | DefaultFullAccessWithNotificationPolicy |
| Anti-spam | **High confidence phishing** | **AdminOnlyAccessPolicy** | **AdminOnlyAccessPolicy** | **AdminOnlyAccessPolicy** |
| Anti-spam | Bulk | DefaultFullAccessPolicy¹ | DefaultFullAccessPolicy | DefaultFullAccessWithNotificationPolicy |
| Anti-phish (all mailboxes) | Spoof | DefaultFullAccessPolicy¹ | DefaultFullAccessPolicy | DefaultFullAccessWithNotificationPolicy |
| Anti-phish (MDO) | User impersonation | DefaultFullAccessPolicy¹ | DefaultFullAccessWithNotificationPolicy | DefaultFullAccessWithNotificationPolicy |
| Anti-phish (MDO) | Domain impersonation | DefaultFullAccessPolicy¹ | DefaultFullAccessWithNotificationPolicy | DefaultFullAccessWithNotificationPolicy |
| Anti-phish (MDO) | Mailbox intelligence impersonation | DefaultFullAccessPolicy¹ | DefaultFullAccessPolicy | DefaultFullAccessWithNotificationPolicy |
| Safe Attachments | Malware/Phish | AdminOnlyAccessPolicy | AdminOnlyAccessPolicy | AdminOnlyAccessPolicy |
| Safe Attachments | Encrypted/unscannable attachment | DefaultFullAccessWithNotificationPolicy | DefaultFullAccessWithNotificationPolicy | DefaultFullAccessWithNotificationPolicy |
| Teams Protection (recommended only, not preset-governed) | Malware, HC Phish | AdminOnlyAccessPolicy | AdminOnlyAccessPolicy | AdminOnlyAccessPolicy |

¹ Some tenants use `NotificationEnabledPolicy` instead — same Full access permissions, notifications on.

**The pattern is completely consistent: only Malware, High-Confidence Phishing, and Safe Attachments malware/phish ever get `AdminOnlyAccessPolicy` ("No access") — literally every other verdict, including all three impersonation types and spoof, uses a Full-access policy even under Strict.** `MET-Teams004`'s existing ZAP-for-Teams check already matches this table exactly (`AdminOnlyAccessPolicy` for Malware/HC-Phish) — cross-check confirms it needs no change.

---

## Confirmed bugs

### Bug 1 — MET-EXO004 always flags `AdminOnlyAccessPolicy` as a false positive

`EXO004` iterates every quarantine policy uniformly and flags `EndUserQuarantinePermissionsValue -eq 0` as an issue ("users cannot review or release quarantined messages"). `AdminOnlyAccessPolicy` *always* has that value — it's "No access" by design and exists on every tenant. This produces a **guaranteed false-positive Warning on every single tenant, every run**, flagging Microsoft's own by-design policy as a misconfiguration. A second, quieter issue: EXO004 reads `$policy.QuarantineRetentionDays`, but `Set-QuarantinePolicy`'s own docs mark that parameter "reserved for internal Microsoft use" — real retention lives on the filter policies, not the quarantine tag object, so this check is likely evaluating a non-functional field.

### Bug 2 — MET-EXO009's risk model contradicts Microsoft's own Strict preset

`EXO009`'s `$verdictRisk` hashtable classifies `Impersonated User`, `Impersonated Domain` as `'High'` risk (must have `PermissionToRelease = $false` to Pass) and `Phish`, `Mailbox Intelligence Phish`, `Spoof` as `'Medium'` (Warning if `PermissionToRelease = $true`). Per the matrix above, **every one of those five verdicts uses a Full-access policy in Microsoft's own Strict preset** (`PermissionToRelease = $true`). EXO009 therefore flags Microsoft's own Strict preset configuration as a Fail (impersonation) or Warning (phish/spoof) on any tenant with Strict or Standard assigned to anyone — i.e., most tenants. This is more severe than Bug 1: it's a `Severity High` hard Fail on a very common configuration, not a Warning.

The only verdicts with an actual restrictive floor in Microsoft's design are **Malware, High-Confidence Phish, and Safe Attachments malware/phish**. Everything else has no floor to enforce — Microsoft itself trusts full-access-with-notification for those, presumably because they carry more false-positive risk and users are meant to self-triage once notified.

---

## Design: preset vs. custom as a first-class distinction

Two independent decisions go into a custom threat policy verdict: the *action* (Quarantine vs. Junk vs. deliver) and, if Quarantine, *which quarantine policy* to attach. Both are only ever admin-configured — and only ever capable of drifting from a sane baseline — on **custom** policies. Preset-covered recipients get both decisions made *for* them by Microsoft, correctly, by construction; a Fail against a preset is never actionable (the admin can't fix it) and never wrong (it's guaranteed to match the matrix above). So preset-generated policy objects should not be evaluated as findings at all - only reported as coverage, which MDO008/013 already do.

This applies uniformly across all three checks, which is why a single shared predicate is worth extracting rather than reimplementing per check:

`Private/Test-METIsPresetSecurityPolicyName.ps1` (already implemented and unit-tested this pass):
- `Test-METIsPresetSecurityPolicyName -Name <string>` — matches `^(Strict|Standard) Preset Security Policy` (same technique already used in `Resolve-METSafeLinksEffectivePolicy`), for classifying `HostedContentFilterPolicy`/`AntiPhishPolicy`/`MalwareFilterPolicy`/`SafeAttachmentPolicy` objects.
- `Test-METIsBuiltInQuarantinePolicyName -Name <string>` — matches the 4 built-in quarantine policy names, for classifying `QuarantinePolicy` objects (a related but distinct list, since these are two different cmdlets' objects).

---

## Implementation plan

### MET-EXO009 — correct the risk model, skip preset objects
Replace `$verdictRisk` with a fixed restricted set: `Malware`, `High-Confidence Phish` only (Safe Attachments malware already buckets into `'Malware'` in the existing code - no change needed there). Drop the `Medium`/Warning tier entirely - it was misfiring against Strict's own spoof/phish/mailbox-intelligence tags the same way the High tier misfired against impersonation. When building `$assignments`, classify each source policy via `Test-METIsPresetSecurityPolicyName` and skip preset-generated ones entirely (their tags are guaranteed correct; nothing to evaluate). The Fail check itself stays exactly as-is otherwise: it already reads the actual `PermissionToRelease` bit, not the tag's name, so a custom quarantine policy that independently implements "no access" for Malware still Passes, and a custom policy pointing Malware at any full-access tag (built-in or custom) still Fails - that symmetry doesn't change.

### MET-EXO008 — preset-aware retention, anti-phish inheritance note
For a `HostedContentFilterPolicy` classified as preset via `Test-METIsPresetSecurityPolicyName`: retention is fixed at 30 days by the matrix above and confirmed non-editable ("You can't change the value in the Standard or Strict preset security policies" — [Quarantine retention](https://learn.microsoft.com/en-us/defender-office-365/quarantine-about#quarantine-retention)). Report it as Info/context, not an actionable Fail with a `Set-HostedContentFilterPolicy` recommendation that would error if run. For custom/default policies, keep the existing 1-30-day Fail-under-30 logic unchanged. Add a note to the Finding/doc that this same retention value governs anti-phishing quarantine (spoof/impersonation) for the same recipient too - confirmed: "This retention period is also controlled by the... setting in anti-spam policies. The retention period is the value from the first matching anti-spam policy that the recipient is defined in." Malware, Safe Attachments, ZAP-for-Teams, and mail-flow-rule quarantine are all fixed at 30 days, non-customizable - out of scope, nothing to check there (same "genuinely nothing to assess" bucket as AIR/SPO from earlier in this pass).

### MET-EXO004 — narrow to what's uniquely its job
Remove the generic no-access and retention checks (Bug 1; redundant with and less accurate than EXO009 and EXO008 respectively). Exclude all 4 built-in quarantine policy names via `Test-METIsBuiltInQuarantinePolicyName` - note `DefaultFullAccessPolicy` itself is "full permissions, no notification" *by design*, so a naive "permission granted but notifications off" check would misfire on it exactly like Bug 1 misfired on `AdminOnlyAccessPolicy` if not excluded. What's left, and unique to EXO004: for genuinely custom quarantine policies, flag `ESNEnabled -eq $false` combined with `EndUserQuarantinePermissionsValue -gt 0` - i.e., users have been granted permission to act on quarantined messages but are never notified that any exist, a real usability/awareness gap distinct from EXO009's per-verdict correctness and the new cadence check below. No custom quarantine policies at all → Pass (nothing to review).

### New: MET-EXO017 — Quarantine Notification Cadence
Info-level, single tenant-wide result. `Get-QuarantinePolicy -QuarantinePolicyType GlobalQuarantinePolicy` (identity `DefaultGlobalTag`) → `EndUserSpamNotificationFrequency` (`TimeSpan`, valid values `04:00:00`/`1.00:00:00`/`7.00:00:00`). No Microsoft-recommended value exists - it's a timeliness/UX trade-off, not a security control - so this surfaces the current cadence for review, same treatment as EXO014/EXO016, not a Pass/Fail assertion.

---

## Verify before coding

- `Get-QuarantinePolicy -QuarantinePolicyType GlobalQuarantinePolicy` returning identity `DefaultGlobalTag` specifically (vs. some other global-settings identity) - confirmed by the doc's own example syntax (`Get-QuarantinePolicy -QuarantinePolicyType GlobalQuarantinePolicy | Set-QuarantinePolicy ...`) but not tenant-verified.
- `EndUserQuarantinePermissionsValue` is documented as present on `Set-QuarantinePolicy`; confirm `Get-QuarantinePolicy` returns the same property name on read (existing EXO004 code already assumes this, so treating as confirmed by prior art).

## Known pre-existing gap noticed during this pass (not in scope)

`MET-EXO007`, `MET-EXO008`, and `MET-EXO009` currently have **zero unit test coverage** - no `Describe 'MET-EXO007...'` etc. anywhere in `Tests/Unit/`. EXO008 and EXO009 get dedicated test files as part of this pass (fixing it for those two as a side effect); EXO007 remains untested and is a candidate for a future pass.
