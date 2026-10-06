# MET-Teams012 - Call Reporting

**Category:** Teams | **Severity:** Medium

## What it checks

Reviews two properties of every Teams calling policy via `Get-CsTeamsCallingPolicy` and emits one result for each:

- **Call reporting availability** (result name `Call Reporting`) - `ReportCall` is present and not set to its default value of `Enabled`, meaning users assigned to that policy do not see the option to report a call as a security concern
- **PSTN call spam filtering** (result name `PSTN Call Spam Filtering`) - `SpamFilteringEnabledType` is `Disabled`, meaning users assigned to that policy get no "Spam Likely" label on inbound phone calls

All returned policies are evaluated, not just `Global` - per-user/group calling policy assignments can silently remove the reporting capability for a subset of users even when the tenant default is healthy.

## Why it matters

Call reporting is the closest native Teams control to helpdesk-vishing attacks - the pattern seen in Storm-1811 and 3AM-style ransomware campaigns, where an attacker calls or Teams-messages a user while impersonating IT support to talk them into installing remote-access tooling or approving an MFA prompt. The "report a call" capability lets a user flag a suspicious call in the moment, giving the security team a signal that would otherwise only surface after the attack succeeded (if at all). Disabling it, whether tenant-wide or on a specific calling policy, removes that early-warning channel for the exact class of social-engineering attack that live voice/video calls are most effective at pulling off.

PSTN call spam filtering covers the same attack from the phone network. Helpdesk-vishing and callback-phishing campaigns ("call this number about your invoice") often land as an ordinary inbound phone call rather than a Teams call. With spam filtering on, Teams screens inbound PSTN calls (including interactive voice response checks where needed) and labels likely spam before the user picks up.

> **Note on `ReportCall`:** the `Set-CsTeamsCallingPolicy` reference (updated September 2026) still says `ReportCall` "has not been fully released yet, so the setting will have no effect", while the Defender for Office 365 What's new page lists call reporting as shipped in March 2026. The cmdlet page looks out of date, but if call reporting doesn't appear for users despite a Pass, check against current Microsoft documentation.

## Pass / Fail / Warning

### Call Reporting

| Result | Condition |
|---|---|
| Pass | Every Teams calling policy has `ReportCall` set to `Enabled` |
| Warning | `ReportCall` was returned for some policies but not others - call reporting was not established for the policies it was absent from, which are named in the finding |
| NotApplicable | `ReportCall` was not returned for any policy - nothing was assessed, so the result is unassessed rather than a pass; the installed `MicrosoftTeams` module version may not expose the property |
| Fail | One or more Teams calling policies have `ReportCall` explicitly set to a value other than `Enabled` |
| Fail | The Teams calling policies could not be retrieved (check itself failed to run). Only this single result is emitted |

### PSTN Call Spam Filtering

| Result | Condition |
|---|---|
| Pass | Every Teams calling policy has `SpamFilteringEnabledType` set to `Enabled` (or another `Enabled*` variant) |
| Warning | `SpamFilteringEnabledType` was absent on some policies, or returned an unrecognized value. The affected policies are named |
| NotApplicable | `SpamFilteringEnabledType` was not returned for any policy. Reported as unassessed, never Pass |
| Fail | One or more policies have `SpamFilteringEnabledType` set to `Disabled` |

## Recommendation

Re-enable call reporting on every flagged policy:

```powershell
Set-CsTeamsCallingPolicy -Identity <name> -ReportCall Enabled
```

Re-enable PSTN call spam filtering on every flagged policy:

```powershell
Set-CsTeamsCallingPolicy -Identity <name> -SpamFilteringEnabledType Enabled
```

`VoicePhishingDetection` (AI detection of vishing during live inbound calls) is also on this cmdlet, but Microsoft marks it as not yet released, so it isn't assessed yet.

## Reference

- [New-CsTeamsCallingPolicy](https://learn.microsoft.com/en-us/powershell/module/microsoftteams/new-csteamscallingpolicy)
- [Set-CsTeamsCallingPolicy](https://learn.microsoft.com/en-us/powershell/module/microsoftteams/set-csteamscallingpolicy)
- [Configure spam filtering for calls in Microsoft Teams](https://learn.microsoft.com/en-us/microsoftteams/configure-call-spam-filtering)
