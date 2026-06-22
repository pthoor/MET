# MET-EXO007 — Transport Rule Audit

**Category:** EXO | **Severity:** Medium

## What it checks

Audits transport rules (mail flow rules) for security-relevant configurations:

- Rules that **set SCL to -1** — bypasses spam filtering entirely for matching messages
- Rules that **disable Safe Links processing** — via header manipulation
- Rules that **set SCL explicitly** (non-bypass) — informational note

This is an **informational / Warning** check — MET cannot determine whether a bypass is intentional and authorised. All findings are surfaced for human review.

## Why it matters

Transport rules that bypass spam filtering or disable Safe Links are a common attack vector for persistence after a compromise (attacker adds a rule to ensure phishing mail is always delivered) and a common misconfiguration (IT added a bypass years ago and forgot about it). Every bypass rule should be documented, reviewed, and scoped as narrowly as possible.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Info | No concerning rules found |
| Warning | Rules bypassing spam filtering or disabling Safe Links detected |

## Recommendation

Review all `SCL=-1` rules. Each one should have a documented business justification and be scoped to the narrowest possible sender/recipient set. Remove rules that are no longer needed. Prefer allow-listing in the Tenant Allow/Block List over transport rule bypasses where possible.

## Reference

- [Mail flow rules in Exchange Online](https://aka.ms/exo-transportrules)
