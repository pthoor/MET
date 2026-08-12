# MET-EXO014 — Advanced Delivery Policy Scope

**Category:** EXO | **Severity:** Medium

## What it checks

Retrieves the enabled rules in the Advanced Delivery policy (`Get-ExoPhishSimOverrideRule`) — the phishing simulation override configuration in Microsoft Defender for Office 365. It reports how many override rules are currently enabled and lists them by name.

The Advanced Delivery policy lets an admin designate specific senders — typically a third-party phishing simulation platform (e.g. KnowBe4, Proofpoint Security Awareness Training) or a SecOps mailbox — whose mail should skip MDO/EOP filtering entirely, so simulated phishing tests and SecOps workflows aren't blocked or rewritten before they reach the intended recipients.

## Why it matters

An Advanced Delivery override is not a narrow allow — it exempts matching mail from **all** filtering: spam, phishing, malware, Safe Links rewriting, Safe Attachments detonation, ZAP, and quarantine. That's the whole point when it's scoped to a legitimate, actively-used phishing simulation vendor: those simulations need to arrive unmodified to be effective.

But the same exemption is dangerous if left unmanaged. A phishing simulation platform that's no longer in use, a vendor whose sending infrastructure has changed, or an entry added years ago and forgotten about is a standing, completely unfiltered inbound channel — an easy way for real attackers to spoof the same sender pattern and land in inboxes with zero MDO inspection. Because this is a scope/presence check only, there is no automated way to confirm from the rule list alone whether an entry is still tied to a live vendor; it requires human review of the tenant's actual simulation program.

## Pass / Fail / Warning

This check is **Info-only** on its substantive branches — there is no "correct" number of override rules, since presence is often legitimate and expected. It only returns `Fail` when the rules cannot be retrieved at all.

| Result | Condition |
|---|---|
| Info | No enabled Advanced Delivery override rules are configured |
| Info | One or more enabled override rules exist — listed by name for review |
| Fail | Unable to retrieve Advanced Delivery rules (e.g. insufficient permissions) |

## Recommendation

Advanced Delivery overrides are meant for third-party phishing simulation platforms and are legitimate when scoped narrowly to the simulation vendor's specific sending infrastructure. Periodically verify each rule is still tied to an active simulation platform or SecOps process — a stale or overly broad override is an unfiltered inbound channel that completely bypasses MDO. Review scope at security.microsoft.com > Email & collaboration > Policies & rules > Threat policies > Advanced delivery.

## Reference

- [Configure the Advanced Delivery policy](https://learn.microsoft.com/en-us/defender-office-365/advanced-delivery-policy-configure)
