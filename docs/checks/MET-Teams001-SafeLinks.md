# MET-Teams001 - Safe Links for Teams

**Category:** Teams | **Severity:** High

## What it checks

Resolves the **effective** Safe Links policy for every assessable mailbox - the same precedence-aware model `MET-MDO001` uses for email - and flags recipients whose effective policy has `EnableSafeLinksForTeams` disabled.

Safe Links is a single policy object shared across Email, Office apps, and Teams (`EnableSafeLinksForEmail`/`EnableSafeLinksForOffice`/`EnableSafeLinksForTeams` are three independent toggles on the same `SafeLinksPolicy`). Precedence works identically regardless of which toggle you care about: Strict preset always wins over Standard preset, which always wins over any custom policy regardless of the custom policy's own priority number; among custom policies, lowest `Priority` number wins; unmatched recipients fall through to the Built-In Protection Policy. This check reuses `Resolve-METSafeLinksEffectivePolicy` (the same resolver MDO001 calls) so a recipient's *actual* effective policy - not just "does a Teams-enabled policy exist somewhere" - determines the result.

**Known limitation (fixed 2026-08-18):** an earlier version of this check only verified that at least one Teams-enabled policy existed and had an enabled rule assigning it. That missed policy *shadowing*: a Teams-enabled policy with a valid assigning rule can still apply to nobody if a higher-precedence policy (a preset, or a lower-priority-number custom policy) wins for those same recipients - and if that higher-precedence policy has Teams disabled, the check would still report Pass. The rewrite catches this because it evaluates the actual effective policy per recipient, not policy existence in isolation.

## Why it matters

Teams is increasingly used as a phishing vector - malicious URLs are posted in chats and channels, often by compromised accounts. Without Safe Links for Teams, URLs shared in Teams are not scanned at click-time and bypass the protections applied to email. A gap here is especially easy to miss because it can hide behind an apparently-correct, Teams-enabled, rule-assigned policy that never actually takes effect for anyone.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | Every assessable mailbox's effective Safe Links policy has `EnableSafeLinksForTeams = true` |
| Fail | At least one mailbox's effective policy has `EnableSafeLinksForTeams = false` |
| Warning | Policy/rule retrieval was incomplete (coverage can't be fully determined), a scoped group couldn't be expanded, or shadowing exists with no current recipient impact |
| NotApplicable | No assessable mailboxes were found in the tenant |

## Recommendation

Assign recipients to a Standard/Strict preset or a compliant custom Safe Links policy with `EnableSafeLinksForTeams` enabled. Fix the *effective* policy for each affected recipient - an unused, shadowed policy having the flag on does not affect this result.

## Reference

- [Safe Links settings for Microsoft Teams](https://aka.ms/mdo-safelinks-teams)
