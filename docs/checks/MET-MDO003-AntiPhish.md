# MET-MDO003 - Anti-Phishing

**Category:** MDO | **Severity:** High

## What it checks

Resolves the effective anti-phishing policy for every assessable mailbox using
Strict preset, Standard preset, enabled custom-policy priority, and the default
anti-phishing policy. It evaluates only policies that currently affect
recipients. Shadowed and inactive policies remain visible. A custom catch-all
that precedes and shadows a specialized custom policy produces a Warning; preset
overlap and expected overlap with a specialized policy remain informational.

For each effective policy it verifies:

- `EnableMailboxIntelligence` - learns from user email patterns to detect impersonation
- `EnableMailboxIntelligenceProtection` - acts on mailbox intelligence signals
- `EnableFirstContactSafetyTips` - warns users when they receive mail from new senders
- `EnableSimilarUsersSafetyTips` / `EnableSimilarDomainsSafetyTips` - visual warnings for lookalike senders
- `EnableTargetedUserProtection` with `TargetedUsersToProtect` - explicit impersonation protection for named users
- `TargetedUserProtectionAction` - action taken when enabled targeted-user impersonation detection matches
- `EnableOrganizationDomainsProtection` and `TargetedDomainProtectionAction` - protection for owned-domain impersonation
- `EnableTargetedDomainsProtection` with `TargetedDomainsToProtect` - impersonation protection for explicitly named external domains (suppliers, partners, customers)
- `MailboxIntelligenceProtectionAction` - action taken for mailbox-intelligence impersonation
- `PhishThresholdLevel` - phishing threshold meets the Standard baseline of 3

## Why it matters

Business email compromise (BEC) attacks rely on impersonation. These settings collectively create defence-in-depth: mailbox intelligence catches subtle behavioural impersonation, safety tips surface visual warnings, and targeted user protection explicitly protects named high-value accounts such as executives.

Owned-domain protection only covers the tenant's own accepted domains. Invoice-redirection and payment-diversion fraud is normally run from a lookalike of a *supplier or partner* domain, which is covered only when that domain is named in `TargetedDomainsToProtect`. A tenant that protects its own domains but no external ones therefore has no impersonation protection over exactly the sender identities its finance function trusts.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | Every assessed mailbox receives an effective policy that meets the baseline |
| Fail | One or more mailboxes receive an effective policy below baseline |
| Warning | Mailbox, rule, policy, group, or precedence retrieval is incomplete |
| NotApplicable | No assessable mailboxes were found |

Custom domain impersonation protection is reported as a gap when
`EnableTargetedDomainsProtection` is off or `TargetedDomainsToProtect` is empty.
When the list is populated its size is written to the verbose stream as
confirmation rather than reported as a finding. A policy object that does not
expose the property at all is not assessed for it.

`TargetedUserProtectionAction = NoAction` is only reported when targeted-user
protection is enabled and has protected users. If targeted-user protection is
disabled or the protected-user list is empty, the report identifies that root
configuration gap without also reporting the inactive action property.

## Recommendation

Apply the **Standard** or **Strict** preset, or manually enable all impersonation and safety-tip settings. Set the action to `Quarantine` rather than `MoveToJmf` for higher-confidence phishing scenarios. If custom policies leave recipients on a weak default, place a compliant catch-all after specialized custom policies.

## Reference

- [Anti-phishing protection in Microsoft 365](https://aka.ms/mdo-antiphishing)
