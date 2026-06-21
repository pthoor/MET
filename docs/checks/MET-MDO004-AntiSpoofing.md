# MET-MDO004 — Anti-Spoofing

**Category:** MDO | **Severity:** High

## What it checks

Verifies anti-spoofing controls within anti-phishing policies:

- `EnableSpoofIntelligence` — spoof intelligence is on
- `AuthenticationFailAction` — action on authentication failure (`Quarantine` preferred over `MoveToJmf`)
- `EnableUnauthenticatedSender` — ? and "via" indicators shown on unauthenticated mail
- `HonorDmarcPolicy` — DMARC `p=reject` / `p=quarantine` is enforced

## Why it matters

Spoofing is the simplest phishing technique and is still prevalent. Spoof intelligence classifies spoofed messages and the `AuthenticationFailAction` determines what happens. Honoring DMARC is critical — without `HonorDmarcPolicy`, domains that have published `p=reject` get no enforcement from EOP.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | All four settings correct |
| Fail | Spoof intelligence disabled |
| Warning | Spoof intelligence on but sub-optimal action or DMARC not honored |

## Recommendation

Enable spoof intelligence, set `AuthenticationFailAction` to `Quarantine`, enable unauthenticated sender indicators, and set `HonorDmarcPolicy` to `true`.

## Reference

- [Anti-spoofing protection in EOP](https://aka.ms/mdo-antispoofing)
