# MET-MDO003 — Anti-Phishing

**Category:** MDO | **Severity:** High

## What it checks

Verifies anti-phishing policy configuration:

- `EnableMailboxIntelligence` — learns from user email patterns to detect impersonation
- `EnableMailboxIntelligenceProtection` — acts on mailbox intelligence signals
- `EnableFirstContactSafetyTips` — warns users when they receive mail from new senders
- `EnableSimilarUsersSafetyTips` / `EnableSimilarDomainsSafetyTips` — visual warnings for lookalike senders
- `EnableTargetedUserProtection` with `TargetedUsersToProtect` — explicit impersonation protection for named users
- `TargetedUserProtectionAction` — action taken on impersonation detection (must not be `NoAction`)

## Why it matters

Business email compromise (BEC) attacks rely on impersonation. These settings collectively create defence-in-depth: mailbox intelligence catches subtle behavioural impersonation, safety tips surface visual warnings, and targeted user protection explicitly protects named high-value accounts such as executives.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | All protections enabled, action is not `NoAction` |
| Fail | One or more settings are not configured |

## Recommendation

Apply the **Standard** or **Strict** preset, or manually enable all impersonation and safety-tip settings. Set the action to `Quarantine` rather than `MoveToJmf` for higher-confidence phishing scenarios.

## Reference

- [Anti-phishing protection in Microsoft 365](https://aka.ms/mdo-antiphishing)
