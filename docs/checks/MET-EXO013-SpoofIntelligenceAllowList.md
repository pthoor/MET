# MET-EXO013 — Spoof Intelligence Allow-List Hygiene

**Category:** EXO | **Severity:** High

## What it checks

Spoof intelligence (part of anti-spoofing protection in Microsoft Defender for Office 365) continuously learns which senders are sending mail that appears to spoof a domain your organization interacts with — for example, a third-party service that sends `noreply@contoso.com`-style mail from its own infrastructure. When spoof intelligence flags one of these patterns, an admin (or, in some configurations, an automatic approval) can allow it: this records a standing exception in the Tenant Allow/Block List that says "let this specific spoofed sender address through when it arrives from this specific sending infrastructure."

This check calls `Get-TenantAllowBlockListSpoofItems -Action Allow` and reviews every such approved spoof pair:

- Total count of allow entries
- How many are `SpoofType = External` — an outside domain or IP approved to send mail that appears to come from an internal or trusted sender address, as opposed to `Internal` (spoofing within your own accepted domains)
- Lists up to 10 sample entries showing the spoofed sender, the true sending infrastructure, and the spoof type

## Why it matters

Each allow entry is a permanent, easy-to-forget exception to anti-spoofing protection. Unlike a rule an admin writes deliberately, many of these entries are created automatically as spoof intelligence learns sending patterns, or reactively during incident response to unblock a legitimate but unusual sender. They are not meant to be permanent — a vendor may change mail infrastructure, decommission a service, or stop sending altogether, but the allow entry stays in place indefinitely unless someone removes it.

An accumulating allow list is a growing attack surface: any entry that was created for a system no longer in use is a standing invitation for that exact spoofed address/infrastructure combination to reach mailboxes without being flagged. `External` entries are the higher-risk half of this list — they let a domain or IP outside your organization present mail as if it came from a sender address your users already trust, which is the exact technique used in business email compromise and vendor impersonation attacks.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Info | No spoof intelligence allow entries exist — no standing exceptions to review |
| Warning | One or more spoof intelligence allow entries exist |
| Fail | Unable to retrieve spoof intelligence allow entries (for example, insufficient permissions) |

## Recommendation

Review each allowed spoof pair periodically rather than treating it as a one-time setup step. Confirm the sender/infrastructure combination is still in active, legitimate use, and remove entries for senders or infrastructure that are no longer needed. Pay closer attention to `External` entries, since they permit an outside domain to impersonate a sender address your organization trusts. To clean up in bulk:

```powershell
Get-TenantAllowBlockListSpoofItems -Action Allow | Remove-TenantAllowBlockListSpoofItems
```

## Reference

- [Get-TenantAllowBlockListSpoofItems](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-tenantallowblocklistspoofitems)
