# MET-EXO012 - Mailbox Forwarding Exfiltration Risk

**Category:** EXO | **Severity:** Critical

## What it checks

Enumerates mailboxes that have mailbox-level automatic forwarding configured, via `Get-EXOMailbox -Properties ForwardingSmtpAddress,ForwardingAddress,DeliverToMailboxAndForward`. For each mailbox found with forwarding set, it reports where mail is being forwarded to and flags whether the forwarding is "silent" - `DeliverToMailboxAndForward` set to `$false`, meaning the forwarded copy is the *only* copy; the mailbox owner never sees it land in their own mailbox.

**Scope limitation (by design, not an oversight):** this check covers mailbox-level forwarding properties only - `ForwardingSmtpAddress`, `ForwardingAddress`, and `DeliverToMailboxAndForward` set via `Set-Mailbox`. It does **not** inspect inbox rules (`Get-InboxRule`) that forward or redirect mail. Inbox-rule-based forwarding is a well-known attacker technique too, but auditing it requires one API call per mailbox, which does not scale to large tenants within a single triage run. Inbox-rule auditing is deferred to a future release.

## Why it matters

Mailbox forwarding to an external address is one of the most common **business email compromise (BEC)** persistence techniques. After an attacker gains access to a mailbox - typically via phishing or credential stuffing - they often configure forwarding so they continue to receive copies of incoming mail (invoices, wire transfer approvals, password reset emails, sensitive attachments) even after the compromised password is reset and MFA is re-enrolled. Because forwarding is a mailbox property rather than a login event, it persists silently and is easy to miss during incident response unless it's specifically audited.

The risk is highest when `DeliverToMailboxAndForward` is `$false`: the mailbox owner never receives a local copy of the forwarded mail, so there is no visual cue - no message in their Inbox or Sent Items - that anything is being exfiltrated. Visible forwarding (`DeliverToMailboxAndForward = $true`) is lower risk in comparison, since the owner does see a copy and may eventually notice unfamiliar forwarding behavior, but it can still represent an intentional and legitimate business configuration (e.g. shared mailbox routing, a departing employee's handoff) that simply warrants confirmation.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Info | No mailboxes found with forwarding configured |
| Warning | One or more mailboxes have `ForwardingSmtpAddress` or `ForwardingAddress` set - always flagged for review, with silent (no local copy) forwarding called out specifically |
| Fail | The check itself could not run (e.g. insufficient permissions) |

## Recommendation

Review each mailbox with forwarding configured. Confirm every entry is a known, intentional business need. Remove unexpected or unexplained forwarding immediately and treat it as a potential account compromise indicator - investigate sign-in logs and recent mailbox rule changes for that account. To remove mailbox-level forwarding:

```powershell
Set-Mailbox -Identity <mailbox> -ForwardingSmtpAddress $null
```

Pay particular attention to entries where `DeliverToMailboxAndForward` is `$false`, since these leave no trace in the owner's own mailbox.

## Reference

- [Get-EXOMailbox](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-exomailbox)
