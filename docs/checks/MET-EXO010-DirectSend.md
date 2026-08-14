# MET-EXO010 - Direct Send / Anonymous Relay Exposure

**Category:** EXO | **Severity:** Critical

## What it checks

Verifies that the `RejectDirectSend` setting is enabled on the organization configuration. When enabled, it blocks unauthenticated users from submitting mail directly to the tenant's MX records and relaying it through accepted domains.

## Why it matters

Direct Send is a mail-submission method that allows unauthenticated clients (such as printers, scanners, and line-of-business applications) to send mail by connecting directly to a tenant's MX record and submitting mail destined for users within the organization or its accepted domains.

When `RejectDirectSend` is disabled (the dangerous state), an attacker can:
1. Connect to the tenant's MX record without authenticating
2. Submit mail claiming to be from an internal user (e.g., `ceo@contoso.com`)
3. Deliver that mail to any recipient, bypassing anti-spoofing controls entirely

This is actively being abused in the wild. The attacker's message never authenticates as external, so DMARC, DKIM, and SPF validation cannot intervene - the spoofing happens at the relay point, not the sender's domain.

Blocking Direct Send forces legitimate senders to authenticate via SMTP AUTH client submission or use a configured mail relay connector, both of which create audit trails and can be restricted to known, trusted applications.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | RejectDirectSend is enabled |
| Fail | RejectDirectSend is disabled or not configured |
| Fail (Error) | Unable to retrieve organization configuration (permissions issue) |

## Recommendation

Run the following command to enable Direct Send blocking:

```powershell
Set-OrganizationConfig -RejectDirectSend $true
```

**Before enabling broadly**, identify any legitimate Direct Send senders in your environment:

- Printers and scanner appliances
- Line-of-business applications
- Legacy third-party mail systems

These applications must be migrated to one of these methods:

1. **SMTP AUTH client submission** - Configure the application to authenticate with an Exchange Online mailbox and send via `smtp.office365.com:587` (STARTTLS) or port 25 (on your relay connector, if restricted)
2. **SMTP relay connector** - Create an inbound connector restricted by sending IP/FQDN and configure the application to relay through it
3. **Authenticated SMTP gateway** - Use a mail relay service that handles credential management and retries

If you do not migrate legitimate senders before enabling `RejectDirectSend`, their mail will start being rejected with an NDR (non-delivery report).

## Reference

- [Set-OrganizationConfig: RejectDirectSend parameter](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-organizationconfig)
- [Direct Send via SMTP - Overview](https://learn.microsoft.com/en-us/exchange/mail-flow-best-practices/mail-flow-best-practices)
