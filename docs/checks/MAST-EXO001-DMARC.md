# MET-EXO001 — DMARC

**Category:** EXO | **Severity:** High

## What it checks

For each authoritative accepted domain:

- DMARC TXT record is present at `_dmarc.<domain>`
- Policy is `quarantine` or `reject` (not `none`)
- Aggregate reporting (`rua=`) is configured
- `*.mail.onmicrosoft.com` service domains are marked `NotApplicable` (Microsoft-managed service routing domains)

For `*.onmicrosoft.com` tenant domains, the recommendation points to Microsoft 365 admin center DNS records (not external registrar DNS).

## Why it matters

DMARC (Domain-based Message Authentication, Reporting and Conformance) ties together SPF and DKIM into an enforcement policy. A policy of `p=none` is monitoring-only — it generates reports but does not protect recipients from spoofed mail. Moving to `p=quarantine` or `p=reject` is the single most impactful email authentication step a domain owner can take.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | Record present, policy is `quarantine` or `reject`, `rua` configured |
| Fail | No record, policy is `none`, or `rua` missing |
| NotApplicable | Domain is `*.mail.onmicrosoft.com` service domain |

## Recommendation

Publish a DMARC record: `v=DMARC1; p=quarantine; rua=mailto:dmarc@<domain>`. Progress to `p=reject` once you are confident all legitimate sending sources are covered by SPF and DKIM.

## Reference

- [Set up DMARC to validate the From address domain](https://aka.ms/dmarc)
