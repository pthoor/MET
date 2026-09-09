# MET-EXO016 - ARC Trusted Sealers Review

**Category:** EXO | **Severity:** Low

## What it checks

Reviews the Authenticated Received Chain (ARC) trusted sealers list - domains that are authorized to vouch for a message's authentication results when ARC sealing is used.

- **Trusted sealers present** - lists all configured sealer domains
- **Sealer legitimacy** - ensures listed domains are actively used mail-modifying services

## Why it matters

ARC (Authenticated Received Chain) is an email authentication mechanism that allows mail-handling services (gateways, mailing list managers, forwarding services) to validate the original message's DMARC/DKIM/SPF results, then "seal" the message before forwarding to prevent tampering. When a domain is added to the trusted sealers list, any message sealed by that domain bypasses normal authentication checks - it vouches for the original sender's authentication state.

Including obsolete, compromised, or unnecessary sealers in the trusted list creates an authentication bypass. Stale entries should be reviewed and removed regularly.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Info | `Get-ArcConfig` returned no output (Microsoft's documented signal for "no trusted ARC sealers configured"), or returned `ArcTrustedSealers` as an empty list, or with one or more sealers |
| NotApplicable | `Get-ArcConfig` returned a configuration object but `ArcTrustedSealers` was absent from it, or present as `$null` - whether any sealers are configured was not established, so this is reported as unassessed rather than as "none configured" |
| Fail | Unable to retrieve ARC configuration (access issue or cmdlet failure) |

Note: This check returns `Info` in every successful case (no output, empty list, or populated) because all can be legitimate - the decision to use ARC and which sealers to trust is configuration-specific, not a security stance that MET judges as Pass/Fail. Per Microsoft's documentation, `Get-ArcConfig` "returns no results" when no trusted ARC sealers are configured, so an empty return is a genuine "none configured" observation. Only a configuration object that comes back *missing* the `ArcTrustedSealers` member is treated as unreadable.

## Recommendation

Review the ARC trusted sealers list quarterly:

1. Identify each listed domain and confirm it is a mail-modifying service you actively use (security gateway, mailing list manager, service provider forwarder, etc.)
2. Remove any sealer domains you no longer use or recognize
3. If you do not use ARC sealing, this list can remain empty
4. The listed value is the sealer's DKIM signing domain (`d=` value from its DKIM public key), not your own tenant domain

Common legitimate sealers include mail service providers (e.g., mailing list platforms, email forwarding services, security gateways).

## Reference

- [Configure Authenticated Received Chain (ARC) in Defender for Office 365](https://learn.microsoft.com/en-us/defender-office-365/email-authentication-arc-configure)
- [Understanding ARC Sealing and Authentication](https://learn.microsoft.com/en-us/defender-office-365/email-authentication-arc)
