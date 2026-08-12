# MET-Teams007 — Guest Messaging/Calling Configuration

**Category:** Teams | **Severity:** Medium

## What it checks

Reviews the tenant-wide guest configuration for Microsoft Teams via `Get-CsTeamsGuestMessagingConfiguration` and `Get-CsTeamsGuestCallingConfiguration`:

- **`AllowUserChat`** — whether guest accounts (added as members of a team) can initiate a 1:1 chat with staff
- **`AllowPrivateCalling`** — whether guest accounts can place private (1:1) calls to staff

This check is deliberately narrow: it does not evaluate `AllowUserEditMessage`, `AllowUserDeleteMessage`, or the Giphy/memes/stickers toggles, since those are UX preferences rather than security controls.

## Why it matters

This is about **guests** — external identities that have been explicitly added as members of a team or channel — not about the two related-but-distinct concepts:

- **Federation / external access (MET-Teams006)** covers whether users from *other* Microsoft 365 tenants can find, call, or chat with your users at all, before any guest relationship exists.
- **Meeting anonymous join (MET-Teams003)** covers whether unauthenticated participants can join a *scheduled meeting* and whether they wait in a lobby.

Once someone is added as a guest, `AllowUserChat` and `AllowPrivateCalling` control what that guest can do *outside* of meetings — starting unsolicited 1:1 chats or calls with staff. Guest accounts are a common target for takeover (they often use weaker or unmanaged identity providers), so a compromised or maliciously-added guest with chat/calling rights can be used to directly message or call staff members, increasing the social-engineering and vishing attack surface. Restricting these rights doesn't prevent guests from participating in team channels and meetings — it only removes the ability to initiate direct, unsolicited contact.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | `AllowUserChat` is `$false` and `AllowPrivateCalling` is `$false` |
| Warning | `AllowUserChat` and/or `AllowPrivateCalling` is `$true`, or either cmdlet could not be queried |

## Recommendation

If guest access is enabled at all for the tenant, consider whether guests need chat-initiation and private-calling rights specifically, distinct from meeting participation. Disable `AllowUserChat` and `AllowPrivateCalling` for guest configurations unless there is a specific collaboration need:

```powershell
Set-CsTeamsGuestMessagingConfiguration -AllowUserChat $false
Set-CsTeamsGuestCallingConfiguration -AllowPrivateCalling $false
```

This is separate from meeting-level controls (see MET-Teams003) and from external tenant federation (see MET-Teams006) — all three should be reviewed together as part of a full guest/external-access posture assessment.

## Reference

- [Get-CsTeamsGuestMessagingConfiguration](https://learn.microsoft.com/en-us/powershell/module/teams/get-csteamsguestmessagingconfiguration)
