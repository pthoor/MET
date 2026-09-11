# MET-EXO007 - Transport Rule Audit

**Category:** EXO | **Severity:** Medium

## What it checks

Retrieves transport rules with `Get-TransportRule -ResultSize Unlimited` and audits the returned rules for security-relevant configurations:

- `SetSCL = -1`, which bypasses spam filtering
- Header manipulation that appears to disable Safe Links processing
- Other explicit `SetSCL` values, which are retained as informational context when no bypass or Safe Links issue is found

## Why it matters

Transport rules that bypass spam filtering or disable Safe Links are a common persistence technique after compromise and a frequent source of long-lived exceptions. A rule that explicitly sets a non-bypass SCL may be legitimate, but still warrants visibility during a mail-flow review.

## Results

| Result | Severity | Condition |
|---|---|---|
| Fail | Medium | `Get-TransportRule` throws. The result is emitted with the retrieval error detail. |
| Info | Medium | No transport rules are returned. |
| Warning | Medium | One or more retrieved rules bypass spam filtering (`SetSCL = -1`) and/or appear to disable Safe Links. The finding lists the affected rules. |
| Info | Medium | Rules are retrieved but none bypass spam filtering or disable Safe Links. If rules explicitly set a non-bypass SCL, they are included as an informational note. |

The check evaluates the rules returned by `Get-TransportRule`; it does not emit a separate Pass result. A tenant with no returned rules receives the informational no-rules result, while successfully retrieved rules produce the existing audit findings above.

## Recommendation

Review every `SCL=-1` bypass and rule that disables Safe Links. Keep only documented, intentional exceptions, scope them to the narrowest practical sender and recipient sets, and remove stale rules. Prefer the Tenant Allow/Block List to broad transport-rule bypasses where possible.

## Reference

- [Mail flow rules in Exchange Online](https://aka.ms/exo-transportrules)
