# MET-EXO004 — Quarantine Policies

**Category:** EXO | **Severity:** Medium

## What it checks

For each quarantine policy:

- `EndUserQuarantinePermissionsValue` — users have at least some permissions (> 0) so they can review quarantined mail
- `QuarantineRetentionDays` — retention is at least 15 days
- High-confidence phish policies — end-user self-release should NOT be enabled

## Why it matters

Quarantine policies control what users can do with their quarantined messages and how long messages are retained. If users have no quarantine permissions, they cannot release legitimate mail that was over-quarantined. Conversely, allowing users to self-release high-confidence phishing messages undermines the protection entirely.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | Adequate permissions, ≥ 15 days retention, phish policies don't allow self-release |
| Warning | Any of the three conditions not met |

## Recommendation

Configure a quarantine policy that gives end users **Limited access** (can review, request release, but not self-release). For high-confidence phish, use **Admin-only access** (no end-user permissions). Set retention to at least 30 days.

## Reference

- [Quarantine policies in Microsoft Defender for Office 365](https://aka.ms/mdo-quarantinepolicies)
