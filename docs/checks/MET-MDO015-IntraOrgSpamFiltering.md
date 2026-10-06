# MET-MDO015 - Intra-Organization Spam Filtering

**Category:** MDO | **Severity:** Medium

## What it checks

Reads `IntraOrgFilterState` from `Get-HostedContentFilterPolicy` for the default anti-spam policy and for each custom policy whose rule (`Get-HostedContentFilterRule`) is enabled. It reports one result per policy. Policies the Standard and Strict presets create are skipped: Microsoft manages their value and admins can't change it.

## Why it matters

`IntraOrgFilterState` decides whether spam and phishing verdicts are **acted on** for mail sent between users in your own organization. When an account is compromised, internal mail is the attacker's next move: a lure from a real colleague's mailbox arrives with internal trust and none of the external-sender signals users are taught to look for. With intra-org filtering off, not even high confidence phishing between internal users is quarantined.

| Value | Internal verdicts acted on |
|---|---|
| `Default` | Currently the same as `HighConfidencePhish` (but see the government-cloud note below) |
| `HighConfidencePhish` | High confidence phishing |
| `Phish` | Phishing and high confidence phishing |
| `HighConfidenceSpam` | High confidence spam, phishing and high confidence phishing |
| `Spam` | All spam and phishing verdicts |
| `Disabled` | None |

Microsoft's Standard and Strict presets both use `Default`, so `Default` passes. **In GCC, GCC High and DoD, Microsoft documents that `Default` currently behaves as `None`.** MET can't tell which cloud a tenant is in, so the Pass finding says so. Government-cloud tenants should set `HighConfidencePhish` or broader explicitly.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | `Default`, `HighConfidencePhish`, `Phish`, `HighConfidenceSpam` or `Spam` |
| Fail | `Disabled` |
| Warning | An unrecognized value, or the property was absent on this policy while other policies returned it |
| NotApplicable | The property was absent on every in-scope policy (module or service version doesn't expose it). Reported as unassessed, never Pass |
| Fail (Error) | Anti-spam policies could not be retrieved |

## Recommendation

```powershell
Set-HostedContentFilterPolicy -Identity '<policy name>' -IntraOrgFilterState Default
```

Consider `Phish` or broader to also act on ordinary phishing between internal users. Check the effect on internal bulk senders (newsletters, HR mail) before going all the way to `Spam`.

## Reference

- [Anti-spam protection - Intra-Organizational messages to take action on](https://learn.microsoft.com/en-us/defender-office-365/anti-spam-protection-about#anti-spam-policies)
- [Recommended settings - IntraOrgFilterState](https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365#anti-spam-policy-settings)
- [Set-HostedContentFilterPolicy](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-hostedcontentfilterpolicy)
