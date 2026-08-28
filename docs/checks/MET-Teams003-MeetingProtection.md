# MET-Teams003 - Meeting Protection

**Category:** Teams | **Severity:** Medium

## What it checks

Assesses Teams meeting and federation security settings:

- `AllowPublicUsers` (federation config) - Skype consumer access should be disabled if not needed
- `AllowAnonymousUsersToJoinMeeting` (meeting policy) - anonymous join without lobby
- `AutoAdmittedUsers` (meeting policy) - should not be `Everyone` (bypasses lobby)
- `AllowExternalNonTrustedMeetingChat` (meeting policy) - external untrusted participants should not have chat access
- `AllowExternalParticipantGiveRequestControl` (meeting policy) - external participants should not be able to request and be granted control of a shared screen
- `AllowAnonymousUsersToStartMeeting` (meeting policy) - unauthenticated participants should not be able to start a meeting with no organiser present

Every meeting policy instance is evaluated, not only `Global`. A property that the policy object does not expose is treated as not enabled.

## Why it matters

Teams meetings are a social engineering vector. Anonymous join and lobby bypass settings can allow attackers to join calls impersonating executives or vendors. External chat from non-trusted participants allows attackers to send malicious links within a meeting. The lobby is a key security control - its bypass should be explicitly authorised for each meeting.

Screen-control handoff extends that from persuasion to hands-on access: an external participant posing as helpdesk or a vendor engineer asks for control of a shared screen and then drives the victim's session directly. Allowing anonymous participants to start a meeting removes the organiser from the room entirely, so lobby settings that assume somebody is present to admit attendees no longer gate anything - an unauthenticated caller can open the meeting and wait for employees to arrive.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | All settings at recommended values |
| Fail | Anonymous join allowed, anonymous users can start meetings, `AutoAdmittedUsers = Everyone`, or PSTN callers bypass the lobby |
| Warning | Skype consumer access, external chat, or external screen-control requests enabled |

## Recommendation

Disable anonymous meeting join. Set `AutoAdmittedUsers` to `EveryoneInSameAndFederatedCompany` or `OrganizerOnly`. Disable `AllowExternalNonTrustedMeetingChat`. Disable `AllowExternalParticipantGiveRequestControl` so external participants cannot take control of a shared screen, and `AllowAnonymousUsersToStartMeeting` so a meeting cannot begin without its organiser. Review Skype consumer access if not required.

## Reference

- [Teams meetings security settings](https://aka.ms/teams-meeting-security)
