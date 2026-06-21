# MET-EXO002 — DKIM

**Category:** EXO | **Severity:** High

## What it checks

For each domain with a DKIM signing configuration:

- `Enabled` — signing is active
- `KeySize` — key is at least 2048 bits
- `Status` — CNAME records are published and valid in DNS

## Why it matters

DKIM (DomainKeys Identified Mail) cryptographically signs outbound messages, allowing receivers to verify that the message was sent by an authorised system and has not been tampered with in transit. A 1024-bit key is considered weak by modern cryptographic standards and should be rotated to 2048-bit.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | Enabled, key ≥ 2048 bits, status `Valid` |
| Fail | Disabled, key < 2048, status not `Valid`, or no configs found |

## Recommendation

Enable DKIM signing in Microsoft 365 Defender for all accepted domains. If the current key is 1024-bit, rotate it via **Email authentication settings → DKIM → Rotate DKIM keys**. Publish the provided CNAME records at your DNS registrar.

## Reference

- [Set up DKIM to sign mail from your domain](https://aka.ms/dkim)
