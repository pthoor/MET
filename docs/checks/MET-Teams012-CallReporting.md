# MET-Teams012 - Call Reporting

**Category:** Teams | **Severity:** Medium

## What it checks

Reviews the `ReportCall` property of every Teams calling policy via `Get-CsTeamsCallingPolicy`:

- **Call reporting availability** - `ReportCall` is present and not set to its default value of `Enabled`, meaning users assigned to that policy do not see the option to report a call as a security concern

All returned policies are evaluated, not just `Global` - per-user/group calling policy assignments can silently remove the reporting capability for a subset of users even when the tenant default is healthy.

## Why it matters

Call reporting is the closest native Teams control to helpdesk-vishing attacks - the pattern seen in Storm-1811 and 3AM-style ransomware campaigns, where an attacker calls or Teams-messages a user while impersonating IT support to talk them into installing remote-access tooling or approving an MFA prompt. The "report a call" capability lets a user flag a suspicious call in the moment, giving the security team a signal that would otherwise only surface after the attack succeeded (if at all). Disabling it, whether tenant-wide or on a specific calling policy, removes that early-warning channel for the exact class of social-engineering attack that live voice/video calls are most effective at pulling off.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | Every Teams calling policy has `ReportCall` set to `Enabled` (or unset, which defaults to `Enabled`) |
| Fail | One or more Teams calling policies have `ReportCall` explicitly set to a value other than `Enabled` |
| Fail | The Teams calling policies could not be retrieved (check itself failed to run) |

## Recommendation

Re-enable call reporting on every flagged policy:

```powershell
Set-CsTeamsCallingPolicy -Identity <name> -ReportCall Enabled
```

## Reference

- [New-CsTeamsCallingPolicy](https://learn.microsoft.com/en-us/powershell/module/microsoftteams/new-csteamscallingpolicy)
