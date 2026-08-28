# MET-EXO019 - SMTP Client Authentication

**Category:** EXO | **Severity:** High

## What it checks

Reads `SmtpClientAuthenticationDisabled` from `Get-TransportConfig` to determine whether legacy SMTP AUTH client submission is turned off tenant-wide. When the tenant-wide setting is correct, the check then enumerates per-mailbox overrides with `Get-EXOCasMailbox` and reports any mailbox that explicitly re-enables SMTP AUTH for itself.

The per-mailbox property is tri-state:

| Value | Meaning |
|---|---|
| `$null` | Inherits the tenant-wide setting |
| `$true` | SMTP AUTH explicitly disabled for this mailbox |
| `$false` | SMTP AUTH explicitly **re-enabled** for this mailbox, overriding the tenant baseline |

One result is emitted. If the tenant-wide setting already fails, mailboxes are not enumerated - the tenant-wide setting already permits SMTP AUTH everywhere, so per-mailbox detail adds nothing.

## Why it matters

SMTP AUTH client submission (`smtp.office365.com:587`) is a basic-authentication endpoint. The client sends a username and password directly over the connection. There is no interactive sign-in, so:

- **No multi-factor prompt is possible.** A stolen or sprayed password is sufficient on its own.
- **Most Conditional Access policy does not apply.** Conditional Access evaluates interactive sign-ins; legacy protocol submission largely sidesteps it, so device compliance, location, and risk-based controls do not gate the connection.
- **It is reachable from anywhere on the internet** and is a long-standing, continuously scanned target for password spray and credential stuffing.

An attacker who obtains one working password can send mail as that user - internal-looking invoice fraud, payroll-redirect requests, or malware to the organisation's own address book - without ever completing an interactive sign-in that would surface in the usual risky-sign-in signals.

Per-mailbox overrides matter as much as the tenant setting. A tenant can look correctly hardened at the transport-config level while a handful of mailboxes - typically service accounts left behind for a printer or a line-of-business application - carry `SmtpClientAuthenticationDisabled = $false` and remain live basic-authentication endpoints. Those service-account mailboxes are usually the weakest ones in the tenant: shared passwords, no MFA, and rarely rotated.

The per-mailbox enumeration degrades non-fatally. If `Get-EXOCasMailbox` fails (for example, the account can read transport configuration but not mailbox CAS settings), the check still reports the tenant-wide result as a Pass and states in the finding that overrides could not be enumerated, with the exception text carried in the `Error` field.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | `SmtpClientAuthenticationDisabled` is `$true` tenant-wide and no mailbox explicitly re-enables it |
| Pass (with Error) | Tenant-wide setting is `$true` but per-mailbox overrides could not be enumerated - stated in the finding |
| Warning | Tenant-wide setting is `$true` but one or more mailboxes set `SmtpClientAuthenticationDisabled = $false` (up to 10 addresses listed, plus the total count) |
| Fail | `SmtpClientAuthenticationDisabled` is `$false` or not configured - SMTP AUTH is enabled tenant-wide |
| Fail (Error) | Unable to retrieve transport configuration (permissions issue) |

## Recommendation

Disable SMTP AUTH tenant-wide, then clear per-mailbox exceptions so those mailboxes inherit the tenant setting:

```powershell
Set-TransportConfig -SmtpClientAuthenticationDisabled $true

Get-EXOCasMailbox -ResultSize Unlimited -Properties SmtpClientAuthenticationDisabled |
    Where-Object { $_.SmtpClientAuthenticationDisabled -eq $false } |
    ForEach-Object { Set-CASMailbox -Identity $_.PrimarySmtpAddress -SmtpClientAuthenticationDisabled $null }
```

**Before turning it off**, inventory what still submits mail with SMTP AUTH - multifunction printers and scanners, monitoring and backup systems, ticketing systems, and line-of-business applications. Anything left behind will start failing to submit mail, usually silently from the application's point of view. Migrate each one to:

1. **OAuth for SMTP AUTH** - where the client supports it, this keeps SMTP submission but replaces the password with a token, so the endpoint is no longer basic authentication.
2. **A dedicated authenticated relay connector** - an inbound connector scoped to the device's source IP or TLS certificate, so the appliance relays without a mailbox password at all.
3. **Microsoft Graph `sendMail`** - for applications you control, an app-only Graph permission scoped with application access policy is preferable to any SMTP path.

Where an exception is genuinely unavoidable, keep it as a narrow per-mailbox override on a dedicated, non-human service mailbox rather than re-enabling SMTP AUTH tenant-wide, and review the list of exceptions on a fixed schedule.

## Reference

- [Enable or disable authenticated client SMTP submission (SMTP AUTH)](https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/authenticated-client-smtp-submission)
- [Set-TransportConfig](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-transportconfig)
- [Set-CASMailbox](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-casmailbox)
- [How to set up a multifunction device or application to send email](https://learn.microsoft.com/en-us/exchange/mail-flow-best-practices/how-to-set-up-a-multifunction-device-or-application-to-send-email-using-microsoft-365-or-office-365)
