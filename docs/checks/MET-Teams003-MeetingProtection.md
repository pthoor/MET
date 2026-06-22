# MET-Teams003 — Meeting Protection

**Category:** Teams | **Severity:** Medium

## What it checks

Assesses Teams meeting and federation security settings:

- `AllowPublicUsers` (federation config) — Skype consumer access should be disabled if not needed
- `AllowAnonymousUsersToJoinMeeting` (meeting policy) — anonymous join without lobby
- `AutoAdmittedUsers` (meeting policy) — should not be `Everyone` (bypasses lobby)
- `AllowExternalNonTrustedMeetingChat` (meeting policy) — external untrusted participants should not have chat access

## Why it matters

Teams meetings are a social engineering vector. Anonymous join and lobby bypass settings can allow attackers to join calls impersonating executives or vendors. External chat from non-trusted participants allows attackers to send malicious links within a meeting. The lobby is a key security control — its bypass should be explicitly authorised for each meeting.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | All settings at recommended values |
| Fail | Anonymous join allowed or `AutoAdmittedUsers = Everyone` |
| Warning | Skype consumer access or external chat enabled |

## Recommendation

Disable anonymous meeting join. Set `AutoAdmittedUsers` to `EveryoneInSameAndFederatedCompany` or `OrganizerOnly`. Disable `AllowExternalNonTrustedMeetingChat`. Review Skype consumer access if not required.

## Reference

- [Teams meetings security settings](https://aka.ms/teams-meeting-security)
