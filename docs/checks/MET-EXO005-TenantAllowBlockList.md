# MET-EXO005 - Tenant Allow/Block List

**Category:** EXO | **Severity:** Low

## What it checks

Reviews entries in the Tenant Allow/Block List (TABL) across Sender, URL, and FileHash list types:

- **Stale allows** - entries not modified in > 90 days or with a past expiration date
- **Wildcard allows** - entries matching `*.domain` or `*` (overly broad)
- **Allow/block ratio** - allows significantly outnumbering blocks

## Why it matters

Allow entries bypass EOP filtering. They are often created during incident response to recover false-positive deliveries and are supposed to be temporary. Stale allows that were never cleaned up represent a permanent bypass of security controls. Wildcard allows are particularly dangerous - they can allow entire domains or TLDs to bypass filtering.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | No stale allows, no wildcards, balanced ratio |
| Warning | Stale allows, wildcard allows, or ratio imbalance detected; one or more list types (Sender/Url/FileHash) could not be retrieved, so the list was only partially assessed and the allow/block ratio was not evaluated; the Advanced Delivery URL allow-list could not be retrieved; or one or more entries did not return a usable `Action` value and could not be classified as Allow or Block |
| Info | No TABL entries exist (and every list type was successfully retrieved) |

## Recommendation

Review all allow entries quarterly. Set expiration dates when creating new allows. Never use wildcard allows unless absolutely necessary and with explicit approval. Use block entries to compensate for legitimate domains that are being abused.

## Reference

- [Manage the Tenant Allow/Block List](https://aka.ms/tabl)
