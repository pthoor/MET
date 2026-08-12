# MET-EXO011 — Mail Flow Connector Hygiene

**Category:** EXO | **Severity:** High

## What it checks

Reviews every **enabled inbound connector** (`Get-InboundConnector`) for two hygiene issues:

- **TLS not required** — `RequireTls` is not `$true`, meaning the connector will accept mail delivered over an unencrypted or opportunistically-encrypted session
- **No sender restriction** — neither `SenderIPAddresses` nor `SenderDomains` is populated, meaning the connector accepts mail from any source that can reach it

Outbound connectors are out of scope for this check.

## Why it matters

Inbound connectors sit **upstream** of every other spam and phishing control in MDO/EOP — Safe Links, Safe Attachments, anti-phish, anti-spam, and DMARC/SPF/DKIM enforcement all run *after* a message has already been accepted and classified by a connector. A connector configured with `OnPremises` or `Partner` type is often used to mark inbound mail as coming from a trusted, authenticated source, which can suppress standard anti-spoofing checks for messages that pass through it.

If such a connector has no `RequireTls` enforcement and no restriction on `SenderIPAddresses`/`SenderDomains`, it effectively becomes an open relay path: anyone who can reach Exchange Online's inbound endpoint can send mail that gets treated as if it originated from a trusted partner or on-premises system — regardless of how tightly the downstream anti-phish and anti-spoof policies are configured. A loosely configured connector can silently undermine every other check in this tool.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | All enabled inbound connectors require TLS and restrict senders by IP or domain |
| Warning | At least one enabled inbound connector does not require TLS, or has no sender IP/domain restriction |
| Info | No enabled inbound connectors exist |
| Fail | Unable to retrieve inbound connectors (permissions or connectivity issue) |

## Recommendation

Review flagged connectors. Set `RequireTls` to `$true` and restrict `SenderIPAddresses`/`SenderDomains` to only the specific partner or on-premises infrastructure that legitimately needs this connector:

```powershell
Set-InboundConnector -Identity <name> -RequireTls $true
```

## Reference

- [Get-InboundConnector](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-inboundconnector)
