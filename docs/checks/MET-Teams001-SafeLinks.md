# MET-Teams001 — Safe Links for Teams

**Category:** Teams | **Severity:** High

## What it checks

Verifies that at least one Safe Links policy has `EnableSafeLinksForTeams` set to `true`.

## Why it matters

Teams is increasingly used as a phishing vector — malicious URLs are posted in chats and channels, often by compromised accounts. Without Safe Links for Teams, URLs shared in Teams are not scanned at click-time and bypass the protections applied to email.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | At least one policy has `EnableSafeLinksForTeams = true` |
| Fail | No policies, or no policy has Teams enabled |

## Recommendation

Enable `EnableSafeLinksForTeams` in a Safe Links policy that covers all Teams users. The Standard and Strict preset policies include this setting automatically.

## Reference

- [Safe Links settings for Microsoft Teams](https://aka.ms/mdo-safelinks-teams)
