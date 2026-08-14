# MET-EXO011 - Mail Flow Connector Hygiene

**Category:** EXO | **Severity:** High

## What it checks

Reviews every **enabled inbound connector** (`Get-InboundConnector`) for two hygiene issues:

- **TLS not required** - `RequireTls` is not `$true`, meaning the connector will accept mail delivered over an unencrypted or opportunistically-encrypted session
- **No authenticated source restriction** - the connector has neither sender IP addresses bound with `RestrictDomainsToIPAddresses` nor a TLS sender certificate configured with `TlsSenderCertificateName`

Outbound connectors are out of scope for this check.

## Why it matters

Inbound connectors sit **upstream** of every other spam and phishing control in MDO/EOP - Safe Links, Safe Attachments, anti-phish, anti-spam, and DMARC/SPF/DKIM enforcement all run *after* a message has already been accepted and classified by a connector. A connector configured with `OnPremises` or `Partner` type is often used to mark inbound mail as coming from a trusted, authenticated source, which can suppress standard anti-spoofing checks for messages that pass through it.

`SenderDomains` limits which claimed sender domains are in scope, but it does not authenticate the sending infrastructure. Without an enforced source IP or TLS certificate binding, an untrusted sender can claim a domain in that list. A loosely configured connector can silently undermine downstream anti-phish and anti-spoof controls.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | All enabled inbound connectors require TLS and authenticate their source using bound IP addresses or a TLS sender certificate |
| Warning | At least one enabled inbound connector does not require TLS or lacks an effective IP/certificate authentication binding |
| Info | No enabled inbound connectors exist |
| Fail | Unable to retrieve inbound connectors (permissions or connectivity issue) |

## Recommendation

Review flagged connectors. Set `RequireTls` to `$true` and authenticate the source using either `SenderIPAddresses` with `RestrictDomainsToIPAddresses`, or a specific `TlsSenderCertificateName`:

```powershell
Set-InboundConnector -Identity <name> -RequireTls $true
```

## Reference

- [Get-InboundConnector](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-inboundconnector)
