# MET-MDO011 — User Tags

**Category:** MDO | **Severity:** Low

## What it checks

- Whether custom user tags (beyond built-in Priority Account) have been created (`Get-Tag`)
- Whether any alert policies reference those tags

## Why it matters

User tags let you group specific populations of users (e.g. "Board Members", "Finance Team") and then filter threat-hunting views, reports, and alert policies by those groups. Without tags, SecOps must manually identify which high-value accounts are affected by each incident.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | Custom tags exist and at least one alert policy references them |
| Warning | No custom tags defined |
| Warning | Tags exist but no alert policies reference them |

## Recommendation

Create tags for your high-risk user populations. Then configure alert policies in Microsoft 365 Defender that trigger notifications when users in those tags are targeted.

## Reference

- [User tags in Microsoft Defender for Office 365](https://aka.ms/mdo-usertags)
