# MET-EXO003 — SPF

**Category:** EXO | **Severity:** High

## What it checks

For each authoritative accepted domain:

- SPF TXT record is present
- Record does not use `+all` (permit all)
- Record uses `-all` (hard fail) rather than `~all` (soft fail)
- Total DNS lookup count stays within the RFC 7208 limit of 10

## Why it matters

SPF (Sender Policy Framework) declares which mail servers are authorised to send mail on behalf of a domain. `+all` is effectively equivalent to no SPF record — it authorises any server in the world. `~all` (soft fail) is better than nothing but many receivers treat it the same as pass. DNS lookup count exceeding 10 causes an SPF `permerror`, which many receivers treat as a fail.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | Record present, `-all`, ≤ 10 DNS lookups |
| Fail | No record or `+all` present |
| Warning | `~all` used, or lookup count > 10 |

## Recommendation

Publish `v=spf1 include:spf.protection.outlook.com -all` as a starting point. Add additional `include:` entries only for legitimate sending services. Use SPF flattening tools or macros if the 10-lookup limit is a constraint.

## Reference

- [Set up SPF to prevent spoofing](https://aka.ms/spf)
