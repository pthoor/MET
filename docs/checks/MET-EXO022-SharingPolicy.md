# MET-EXO022 - Calendar and Contact Sharing Policies

**Category:** EXO | **Severity:** Medium

## What it checks

Enumerates every sharing policy returned by `Get-SharingPolicy` and emits one result per policy, inspecting the `Domains` collection for entries scoped to `*` (every domain) or `Anonymous` (unauthenticated web sharing links).

Each `Domains` entry is shaped `<domain>:<SharingAction>` - for example `*:CalendarSharingFreeBusySimple`, `Anonymous:CalendarSharingFreeBusyReviewer`, or `contoso.com:ContactsSharing`. A single entry can carry several comma-joined actions. The check treats the text before the first `:` as the domain and the remainder as the action.

Policies where `Enabled` is `$false` are reported as Info - they exist but apply to no mailbox, so they are neither a pass nor a finding.

## Why it matters

Sharing policies govern what a mailbox may publish outside the organization. The three levels are not equivalent:

- **Free/busy simple** exposes only that a block of time is busy. It leaks no content.
- **Free/busy with reviewer or detail** exposes meeting subjects, locations, organizers, and attendee lists.
- **Contacts sharing** exposes the internal address book entries a user holds.

Granting anything above free/busy simple to `*` or `Anonymous` hands an attacker the reconnaissance that internal-impersonation phishing is built from, without any authentication and without touching the tenant. Meeting subjects and attendee lists reveal the reporting structure, which projects are live, which executives are travelling, and when the finance team meets. Contact sharing hands over internal addresses and display names directly.

That material is the difference between a generic phish and a convincing one. A pretext that names a real meeting, a real project, and a real attendee, sent while the named approver is genuinely out of the office, defeats the recipient's normal scepticism - and none of it required a compromised account to assemble.

An `Anonymous` entry is worse than `*` in one respect: it produces sharing URLs that require no authentication at all, so anyone holding the link, including someone it was forwarded to, can read the shared data.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | An enabled policy with no `*` or `Anonymous` entries - all sharing is scoped to named domains |
| Pass | An enabled policy whose `*` or `Anonymous` entries share simple free/busy only (stated explicitly in the finding) |
| Pass | An enabled policy with no sharing domain entries at all |
| Warning | An enabled policy where a `*` or `Anonymous` entry grants more than simple free/busy - the action contains `Reviewer`, `Detail`, or `ContactsSharing` |
| Info | The policy exists but is disabled, or the tenant has no sharing policies |
| Fail (Error) | Unable to retrieve sharing policies (permissions issue) |

## Recommendation

Scope sharing to the partner domains that actually need it, rather than to every domain:

```powershell
Set-SharingPolicy -Identity 'Default Sharing Policy' `
    -Domains 'partner.example:CalendarSharingFreeBusyDetail', 'contoso.com:CalendarSharingFreeBusySimple'
```

Where a wildcard entry is genuinely required - most tenants want some level of external free/busy lookup so that meeting scheduling works - keep it at the simple level:

```powershell
Set-SharingPolicy -Identity 'Default Sharing Policy' -Domains '*:CalendarSharingFreeBusySimple'
```

Remove `Anonymous` entries unless anonymous calendar publishing is a deliberate, documented requirement, and remove `ContactsSharing` from any wildcard or anonymous entry - there is no scenario where the whole internet needs the internal address book.

If a sharing policy is no longer used, disable or delete it rather than leaving it configured, so that a future assignment cannot silently re-enable broad sharing.

## Reference

- [Sharing policies in Exchange Online](https://learn.microsoft.com/en-us/exchange/sharing/sharing-policies/sharing-policies)
- [Set-SharingPolicy](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-sharingpolicy)
- [Create a sharing policy](https://learn.microsoft.com/en-us/exchange/sharing/sharing-policies/create-a-sharing-policy)
