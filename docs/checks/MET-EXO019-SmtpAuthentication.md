# MET-EXO019 - SMTP Client Authentication

**Category:** EXO | **Severity:** High

## What it checks

Reads `SmtpClientAuthenticationDisabled` from `Get-TransportConfig` to determine whether SMTP AUTH client submission is turned off tenant-wide. When the tenant-wide setting is correct, the check then enumerates per-mailbox overrides with `Get-EXOCasMailbox` and reports any mailbox that explicitly re-enables SMTP AUTH for itself.

The per-mailbox property is tri-state:

| Value | Meaning |
|---|---|
| `$null` | Inherits the tenant-wide setting |
| `$true` | SMTP AUTH explicitly disabled for this mailbox |
| `$false` | SMTP AUTH explicitly **re-enabled** for this mailbox, overriding the tenant baseline |

One result is emitted. If the tenant-wide setting already fails, mailboxes are not enumerated - the tenant-wide setting already permits SMTP AUTH everywhere, so per-mailbox detail adds nothing.

## Why it matters

`SmtpClientAuthenticationDisabled` is a **protocol-level** switch. Per Microsoft's own documentation, "SMTP AUTH supports modern authentication (Modern Auth) through OAuth in addition to basic authentication" - so this setting being enabled does not by itself prove a password-only endpoint is exposed, and this check does not claim it does. Basic authentication for the protocol is governed separately, by an authentication policy (`Set-AuthenticationPolicy -AllowBasicAuthSmtp $false`); where that policy blocks Basic, clients cannot use SMTP AUTH with a password even when the transport-config setting permits the protocol.

What the tenant-wide setting does tell you is scope. Enabled tenant-wide means *every* mailbox in the organisation can submit over SMTP AUTH, not just the ones that need it - and Microsoft's explicit recommendation is the opposite: "disable SMTP AUTH in your Exchange Online organization, and enable it only for the accounts (mailboxes) that still require it."

That scope matters because of what SMTP AUTH permits when Basic is *not* separately blocked. The client sends a username and password directly over the connection, with no interactive sign-in, so:

- **No multi-factor prompt is possible.** A stolen or sprayed password is sufficient on its own.
- **Most Conditional Access policies do not apply.** Conditional Access evaluates interactive sign-ins; legacy protocol submission largely sidesteps it, so device compliance, location, and risk-based controls do not gate the connection.
- **It is reachable from anywhere on the internet** and is a long-standing, continuously scanned target for password spray and credential stuffing.

An attacker who obtains one working password can then send mail as that user - internal-looking invoice fraud, payroll-redirect requests, or malware to the organisation's own address book - without ever completing an interactive sign-in that would surface in the usual risky-sign-in signals.

Per-mailbox overrides matter as much as the tenant setting. A tenant can look correctly hardened at the transport-config level while a handful of mailboxes - typically service accounts left behind for a printer or a line-of-business application - carry `SmtpClientAuthenticationDisabled = $false` and remain live submission endpoints. Those service-account mailboxes are usually the weakest ones in the tenant: shared passwords, no MFA, and rarely rotated.

The per-mailbox enumeration degrades non-fatally, but not silently. If `Get-EXOCasMailbox` fails (for example, the account can read transport configuration but not mailbox CAS settings), the check reports **Warning** rather than Pass: the tenant-wide setting is confirmed correct, but the override exposure the check exists to find is unverified, and a Pass would contribute a full passing score to a posture index for an assessment that did not actually happen. The exception text is carried in the `Error` field.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | `SmtpClientAuthenticationDisabled` is `$true` tenant-wide and no mailbox explicitly re-enables it |
| Warning (with Error) | Tenant-wide setting is `$true` but per-mailbox overrides could not be enumerated - the override exposure is unverified, stated in the finding |
| Warning | Tenant-wide setting is `$true` but one or more mailboxes set `SmtpClientAuthenticationDisabled = $false` (up to 10 addresses listed, plus the total count) |
| Fail | `SmtpClientAuthenticationDisabled` is `$false` or not configured - SMTP AUTH is enabled for every mailbox tenant-wide |
| Fail (Error) | Unable to retrieve transport configuration (permissions issue) |

## Recommendation

Disable SMTP AUTH tenant-wide, then clear per-mailbox exceptions so those mailboxes inherit the tenant setting:

```powershell
Set-TransportConfig -SmtpClientAuthenticationDisabled $true

Get-EXOCasMailbox -ResultSize Unlimited -Properties SmtpClientAuthenticationDisabled |
    Where-Object { $_.SmtpClientAuthenticationDisabled -eq $false } |
    ForEach-Object { Set-CASMailbox -Identity $_.PrimarySmtpAddress -SmtpClientAuthenticationDisabled $null }
```

Block Basic authentication for the protocol separately. This is the control that closes the password-only path, and it is independent of the switch above - OAuth-capable SMTP clients keep working:

```powershell
Set-AuthenticationPolicy -Identity <policy> -AllowBasicAuthSmtp $false
```

**Before turning it off**, inventory what still submits mail with SMTP AUTH - multifunction printers and scanners, monitoring and backup systems, ticketing systems, and line-of-business applications. Anything left behind will start failing to submit mail, usually silently from the application's point of view. Migrate each one to:

1. **OAuth for SMTP AUTH** - where the client supports it, this keeps SMTP submission but replaces the password with a token, so the endpoint is no longer basic authentication. Note that this requires the mailbox to retain SMTP AUTH (a per-mailbox `$false`); the tenant-wide switch disables the protocol for OAuth clients too.
2. **A dedicated authenticated relay connector** - an inbound connector scoped to the device's source IP or TLS certificate, so the appliance relays without a mailbox password at all.
3. **Microsoft Graph `sendMail`** - for applications you control, an app-only Graph permission scoped with application access policy is preferable to any SMTP path.

Where an exception is genuinely unavoidable, keep it as a narrow per-mailbox override on a dedicated, non-human service mailbox rather than re-enabling SMTP AUTH tenant-wide, and review the list of exceptions on a fixed schedule.

## Reference

- [Enable or disable authenticated client SMTP submission (SMTP AUTH)](https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/authenticated-client-smtp-submission)
- [Set-TransportConfig](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-transportconfig)
- [Set-CASMailbox](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-casmailbox)
- [How to set up a multifunction device or application to send email](https://learn.microsoft.com/en-us/exchange/mail-flow-best-practices/how-to-set-up-a-multifunction-device-or-application-to-send-email-using-microsoft-365-or-office-365)
