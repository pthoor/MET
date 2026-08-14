# MET-EXO014 - Advanced Delivery Policy Scope

**Category:** EXO | **Severity:** Medium

## What it checks

Retrieves enforceable phishing simulation and SecOps mailbox rules in the Advanced Delivery policy using `Get-ExoPhishSimOverrideRule` and `Get-ExoSecOpsOverrideRule`. It reports how many override rules are active and lists them by type and name.

The Advanced Delivery policy lets an admin designate third-party phishing simulation infrastructure or dedicated SecOps mailboxes for special delivery handling. Matching messages bypass significant filtering and ZAP actions; malware filtering is bypassed for SecOps mailboxes specifically.

## Why it matters

An Advanced Delivery override is not a conventional narrow allow. It suppresses normal filtering actions and detonation behavior so simulations or SecOps workflows arrive as intended. That is useful when deliberately and narrowly scoped, but it creates a meaningful bypass path if the configuration becomes stale or overly broad.

But the same exemption is dangerous if left unmanaged. A phishing simulation platform that's no longer in use, a vendor whose sending infrastructure has changed, or an entry added years ago and forgotten about is a standing, completely unfiltered inbound channel - an easy way for real attackers to spoof the same sender pattern and land in inboxes with zero MDO inspection. Because this is a scope/presence check only, there is no automated way to confirm from the rule list alone whether an entry is still tied to a live vendor; it requires human review of the tenant's actual simulation program.

## Pass / Fail / Warning

This check is **Info-only** on its substantive branches - there is no "correct" number of override rules, since presence is often legitimate and expected. It only returns `Fail` when the rules cannot be retrieved at all.

| Result | Condition |
|---|---|
| Info | No enforceable Advanced Delivery override rules are configured |
| Info | One or more enforceable phishing simulation or SecOps mailbox rules exist - listed for review |
| Fail | Either required Advanced Delivery rule collection cannot be retrieved |

## Recommendation

Advanced Delivery overrides are meant for third-party phishing simulation platforms and are legitimate when scoped narrowly to the simulation vendor's specific sending infrastructure. Periodically verify each rule is still tied to an active simulation platform or SecOps process - a stale or overly broad override is an unfiltered inbound channel that completely bypasses MDO. Review scope at security.microsoft.com > Email & collaboration > Policies & rules > Threat policies > Advanced delivery.

## Reference

- [Configure the Advanced Delivery policy](https://learn.microsoft.com/en-us/defender-office-365/advanced-delivery-policy-configure)
