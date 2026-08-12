# MET-MDO013 — Preset vs. Custom Policy Precedence Conflicts

**Category:** MDO | **Severity:** High

## What it checks

Cross-references every enabled custom EOP/MDO rule (custom anti-spam via `Get-HostedContentFilterRule`, custom Safe Links via `Get-SafeLinksRule`, custom Anti-Phish via `Get-AntiPhishRule`) against the tenant's per-mailbox preset coverage matrix (the same matrix built by MET-MDO008 via `Resolve-METCoverageMatrix`). For each custom rule, it expands the rule's `SentTo` / `SentToMemberOf` / `RecipientDomainIs` conditions into the actual set of mailboxes it targets, then checks whether any of those mailboxes are also covered by a **Standard** or **Strict** preset security policy.

If a custom rule's target list overlaps with mailboxes already claimed by a preset, that overlap is flagged — the custom rule's settings do not take effect for those mailboxes, no matter what the rule itself says.

## Why it matters

Exchange Online's policy precedence is fixed and non-negotiable: **Strict and Standard preset security policies always outrank any custom policy**, regardless of the custom policy's own `Priority` number. A custom rule can have `Priority 0`, look perfectly scoped in the admin center, and show `State: Enabled` — and still be completely inert for any mailbox that a preset also claims, because the preset wins the precedence contest before the custom rule is ever evaluated.

This produces a dangerous blind spot: an admin builds a custom Anti-Phish rule with tighter settings for a VIP group, verifies it looks "on" and "targeting the right people," and moves on — never realizing that every one of those VIPs is also swept into the Standard preset, which silently overrides the custom rule's settings entirely. The custom configuration exists, is enabled, and is completely ignored.

**How this differs from MET-MDO008:** MDO008 finds mailboxes with **no** preset or custom coverage at all — a pure coverage gap. MET-MDO013 finds the opposite and more insidious pattern: mailboxes with coverage from **two** policies at once, where only one (the preset) actually wins, and the second (the custom rule) is silently shadowed. MDO008's coverage matrix resolution deliberately shows only the winning tier per mailbox — it never separately flags "a custom rule also matched here but lost." MET-MDO013 exists specifically to surface that hidden case.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | No custom EOP/MDO rule's targeted recipients overlap with mailboxes already covered by a Standard/Strict preset — every custom rule is either scoped to uncovered mailboxes or is the winning policy |
| Warning | One or more custom rules target mailboxes that are also covered by a Standard/Strict preset, so the custom rule's settings are silently overridden for those mailboxes |
| Fail | Unable to retrieve the mailbox list needed to assess precedence |
| NotApplicable | No mailboxes found in the tenant |

## Recommendation

For each conflicting rule reported:

1. Decide whether the overlap is intentional. If the custom rule is meant to apply stricter or different settings than the preset for the overlapping mailboxes, either move those mailboxes out of the preset's scope, or raise the preset tier so it matches (or exceeds) what the custom rule intends.
2. If the custom rule is now redundant — because a preset already covers the same mailboxes at an equal or higher protection tier — remove or narrow the custom rule to avoid future confusion and maintenance drift.
3. To confirm the effective policy actually applied to specific users, use Microsoft's [MDOThreatPolicyChecker](https://microsoft.github.io/CSS-Exchange/M365/MDO/MDOThreatPolicyChecker/) rather than relying on a rule's `Enabled`/`Priority` fields alone.

## Reference

- [Preset security policies in EOP and Microsoft Defender for Office 365](https://learn.microsoft.com/en-us/defender-office-365/preset-security-policies)
- [MDOThreatPolicyChecker](https://microsoft.github.io/CSS-Exchange/M365/MDO/MDOThreatPolicyChecker/)
