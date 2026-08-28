# MET-EXO020 - Connection Filter Policy Hygiene

**Category:** EXO | **Severity:** High

## What it checks

Enumerates every connection filter policy returned by `Get-HostedConnectionFilterPolicy` and emits one result per policy, inspecting:

- `IPAllowList` - source IP addresses and CIDR ranges whose mail is exempted from filtering
- Broad CIDR ranges inside that allow list - any IPv4 entry with a prefix shorter than `/24`
- `EnableSafeList` - the third-party-sourced safe list
- `IPBlockList` - reported for context only; block entries are not a finding

Entries that cannot be parsed as an IPv4 CIDR block (a bare IP, an `a.b.c.d-w.x.y.z` range, an IPv6 prefix, or malformed text) are skipped for the broad-range test rather than treated as an error.

## Why it matters

An IP allow list entry is the single most powerful bypass in Exchange Online mail flow. Mail arriving from a listed source IP skips spam filtering **and** spoof intelligence entirely. It is not a scoring adjustment or a lowered threshold - the message is not evaluated.

The practical consequence: any attacker who can get mail relayed through a listed host inherits a trusted path into every mailbox in the tenant. That host does not have to be compromised in a dramatic way. Shared marketing platforms, hosted appliances, a partner's ageing on-premises relay, or a cloud provider address that was reassigned after the allow-list entry was written all produce the same result. Because the message bypasses spoof intelligence too, the sender can claim an internal address and no anti-spoofing control will intervene.

A broad CIDR range multiplies that exposure. A `/16` covers 65,534 addresses; a `/8` covers over 16 million. Almost none of them belong to the organization that the entry was added for, and the tenant has no visibility into who occupies the rest of the range at any given moment.

`EnableSafeList` is a related but distinct problem: it is an externally sourced allow list of senders, and its contents are not enumerable or auditable from PowerShell. An administrator cannot answer the question "which senders are currently bypassing filtering because of this setting?" - which makes it impossible to review, and impossible to reason about during an incident.

The correct home for a genuinely trusted sender is an authenticated inbound connector bound to a certificate or to IP-plus-TLS, where the sender is authenticated rather than merely allow-listed, and where the mail is still filtered. `MET-EXO011` assesses those connectors.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | `IPAllowList` is empty and `EnableSafeList` is disabled |
| Warning | `IPAllowList` is empty but `EnableSafeList` is enabled |
| Fail | `IPAllowList` contains one or more entries (broad ranges shorter than `/24` are called out separately in the finding) |
| Info | The tenant returned no connection filter policies |
| Fail (Error) | Unable to retrieve connection filter policies (permissions issue) |

## Recommendation

Empty the allow list and disable the safe list on the affected policy:

```powershell
Set-HostedConnectionFilterPolicy -Identity 'Default' -IPAllowList @()
Set-HostedConnectionFilterPolicy -Identity 'Default' -EnableSafeList $false
```

Before removing entries, identify what each one was added for. Re-home each genuinely trusted sender onto an authenticated inbound connector rather than an allow-list entry:

```powershell
New-InboundConnector -Name 'Trusted Partner Relay' -ConnectorType Partner `
    -SenderDomains 'partner.example' -SenderIPAddresses '203.0.113.10' `
    -RestrictDomainsToIPAddresses $true -RequireTls $true
```

A connector binds the sender domain to authenticated sending infrastructure and keeps filtering in place, which an allow-list entry does not. Where an entry exists to stop a specific false positive, prefer a targeted Tenant Allow/Block List entry (which expires and is auditable) over a permanent IP exemption.

## Reference

- [Configure connection filtering](https://learn.microsoft.com/en-us/defender-office-365/connection-filter-policies-configure)
- [Set-HostedConnectionFilterPolicy](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-hostedconnectionfilterpolicy)
- [Configure mail flow using connectors](https://learn.microsoft.com/en-us/exchange/mail-flow-best-practices/use-connectors-to-configure-mail-flow/use-connectors-to-configure-mail-flow)
