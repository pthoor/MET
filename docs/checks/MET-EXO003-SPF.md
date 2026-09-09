# MET-EXO003 - SPF

**Category:** EXO | **Severity:** High

## What it checks

For each authoritative accepted domain:

- SPF TXT record is present
- Record's `all` mechanism (if any) does not resolve to `+all` (permit all) or `?all` (neutral)
- Record uses `-all` (hard fail) rather than `~all` (soft fail)
- Record with no `all` term at all and no `redirect=` deferral is treated as no protection, same as a missing record
- Total DNS lookup count stays within the RFC 7208 limit of 10, and was actually possible to count in full

## Why it matters

SPF (Sender Policy Framework) declares which mail servers are authorised to send mail on behalf of a domain. `+all` is effectively equivalent to no SPF record - it authorises any server in the world. `?all` (neutral) is the same: RFC 7208 §2.6.2 requires receivers to treat a neutral result "exactly like the None result" - the result produced when no SPF record exists at all - so a record ending in `?all`, or with no `all` term and no `redirect=` deferral, gives a domain no more protection than publishing nothing. `~all` (soft fail) is a distinct, weaker-than-hard-fail receiver behaviour, not an absence, and remains a Warning. DNS lookup count exceeding 10 causes an SPF `permerror`, which many receivers treat as a fail. If a nested `include:` lookup fails or the include chain runs deeper than the walk can follow, the counted total is a lower bound, not a fact - the check reports that incompleteness rather than passing on an unverified count.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | Record present, `-all`, ≤ 10 DNS lookups, and the lookup count was fully verified |
| Fail | No record; `+all`; `?all` (neutral); or no `all` term and no `redirect=` deferral |
| Warning | `~all` used; `redirect=` deferral with no `all` term; lookup count > 10; or the lookup count could not be fully verified (a nested lookup failed, or the include chain exceeded the depth the walk could follow) |

## Recommendation

Publish `v=spf1 include:spf.protection.outlook.com -all` as a starting point. Add additional `include:` entries only for legitimate sending services. Use SPF flattening tools or macros if the 10-lookup limit is a constraint.

## Reference

- [Set up SPF to prevent spoofing](https://aka.ms/spf)
