# MET-EXO018 - Remote Domain Automatic Forwarding

**Category:** EXO | **Severity:** High

## What it checks

Enumerates every remote domain entry with `Get-RemoteDomain` and reports the `AutoForwardEnabled` setting on each one. The tenant-wide default entry (`DomainName = '*'`) is graded separately from specific, named remote domains, because the two represent very different amounts of exposure. One result is emitted per remote domain.

## Why it matters

A remote domain entry controls how Exchange Online treats mail destined for a given external domain. `AutoForwardEnabled` on that entry decides whether mail may be *automatically* forwarded out of the tenant to that domain - both through inbox rules a user (or an attacker) creates, and through a forwarding SMTP address configured on a mailbox.

When it is enabled on the default `*` entry, automatic forwarding is permitted from any mailbox to every external domain on the internet. That is the standard business email compromise exfiltration path:

1. An attacker phishes or password-sprays a mailbox and signs in.
2. They create an inbox rule that forwards incoming mail to an address they control, often combined with a rule that deletes the forwarded copy so the victim never sees it.
3. They lose access when the password is reset - but the forwarding rule survives, and they keep receiving a copy of the victim's mail, including invoices, contract negotiations, and password-reset messages.

Forwarding is also a straightforward data-exfiltration channel that leaves no obvious trace for the mailbox owner and does not require the attacker to keep a session alive.

This check covers only one of **three independent control planes** for automatic forwarding. All three must be closed for forwarding to actually be blocked:

| Control plane | Where it lives | Assessed by |
|---|---|---|
| Remote domain `AutoForwardEnabled` | `Get-RemoteDomain` | MET-EXO018 (this check) |
| Outbound spam filter policy `AutoForwardingMode` | `Get-HostedOutboundSpamFilterPolicy` | MET-MDO007 |
| Per-mailbox forwarding address | `Get-EXOMailbox` | MET-EXO012 |

Closing one while leaving the others open still permits mail to leave the tenant automatically.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | `AutoForwardEnabled` is disabled for the remote domain |
| Pass | `AutoForwardEnabled` is absent or null on the object - forwarding is not asserted as enabled, and the finding states that the property was not present |
| Warning | `AutoForwardEnabled` is enabled for a specific (non-`*`) remote domain - a scoped exception that needs periodic review |
| Fail | `AutoForwardEnabled` is enabled on the tenant-wide default remote domain (`DomainName = '*'`) |
| Info | No remote domains are configured in the tenant |
| Fail (Error) | Unable to retrieve remote domain configuration (permissions issue) |

## Recommendation

Disable automatic forwarding on the affected remote domain:

```powershell
Set-RemoteDomain -Identity 'Default' -AutoForwardEnabled $false
```

Then close the other two control planes so forwarding is genuinely blocked:

```powershell
Set-HostedOutboundSpamFilterPolicy -Identity 'Default' -AutoForwardingMode Off

Get-EXOMailbox -ResultSize Unlimited -PropertySets Delivery |
    Where-Object { $_.ForwardingSmtpAddress -or $_.ForwardingAddress }
```

**Before disabling**, confirm no business process depends on forwarding to the affected domain. Common legitimate cases include mail routed to a ticketing or archiving system, a shared mailbox mirrored to a partner organisation, and users who forward to a personal address by arrangement. Disabling automatic forwarding breaks these silently from the user's point of view - affected senders are not notified that their forwarding has stopped. Where a genuine need exists, prefer a specific remote domain entry for that destination over re-opening the tenant-wide `*` entry.

## Reference

- [Remote domains in Exchange Online](https://learn.microsoft.com/en-us/exchange/mail-flow-best-practices/remote-domains/remote-domains)
- [Set-RemoteDomain](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-remotedomain)
- [Control automatic external email forwarding in Microsoft 365](https://learn.microsoft.com/en-us/defender-office-365/outbound-spam-policies-external-email-forwarding)
