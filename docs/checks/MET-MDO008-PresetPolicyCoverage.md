# MET-MDO008 — Preset Policy Coverage

**Category:** MDO | **Severity:** Medium

## What it checks

Determines what percentage of tenant mailboxes are covered by the **Standard** or **Strict** preset security policy. Coverage is assessed by expanding:

- Direct `SentTo` assignments
- `SentToMemberOf` distribution group membership
- `RecipientDomainIs` domain-based assignments

## Why it matters

Custom policies require ongoing maintenance and can drift from best-practice baselines. Microsoft's preset policies are continuously updated to reflect current threat intelligence. Any mailbox not covered by a preset (or an equivalent well-maintained custom policy) represents a coverage gap.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | All mailboxes covered by Standard or Strict preset |
| Warning | One or more mailboxes not covered |

## Notes

This check cannot assess whether custom policies for uncovered mailboxes provide equivalent protection — it only reports coverage gaps for human review.

## Reference

- [Preset security policies in EOP and Microsoft Defender for Office 365](https://aka.ms/mdo-presetpolicies)
