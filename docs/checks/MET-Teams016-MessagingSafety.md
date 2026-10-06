# MET-Teams016 - Teams Messaging Safety

**Category:** Teams | **Severity:** High

## What it checks

Reads three tenant-wide settings from `Get-CsTeamsMessagingConfiguration` and reports one result per setting:

| Setting | Teams admin center label | Severity |
|---|---|---|
| `FileTypeCheck` | Messaging settings > Messaging safety > **Scan messages for file types that are not allowed** | High |
| `UrlReputationCheck` | Messaging settings > Messaging safety > **Scan messages for unsafe URLs** | Medium |
| `ReportIncorrectSecurityDetections` | Lets users report a file or URL detection they think is wrong | Low |

## Why it matters

These are Teams' own built-in protections. They work for every Teams user and **don't need a Defender for Office 365 licence**. On a tenant without MDO they are the only file-type and link protection in Teams chat at all, and on an MDO tenant they add a layer alongside Safe Attachments and Safe Links for Teams (MET-Teams001, MET-Teams002).

- **Weaponizable file protection** blocks the whole message, not just the attachment, when it carries a file type commonly used to deliver malware (`.exe`, `.iso`, `.lnk`, `.hta`, `.msi`, `.vbs` and about 50 others). Admins can't configure the list.
- **Malicious URL protection** checks links in chats, channels and meeting chats against threat intelligence and shows a warning to the sender and every recipient. It warns but doesn't block on click. That's Safe Links' job.
- **Report incorrect security detections** gives users a way to flag false positives. It doesn't protect anything by itself, so turning it off is graded a Warning rather than a Fail. But false positives with nowhere to go tend to end with the protection being switched off.

In external conversations, file and URL protection apply to everyone if **any** participating organization has them on. Turning them off therefore exposes your internal chats, and chats with partners who have also turned them off, the most.

Microsoft has said these protections are part of the baseline for new tenants, but older tenants can still have them switched off.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | The setting is `Enabled` |
| Fail | `FileTypeCheck` or `UrlReputationCheck` is `Disabled` |
| Warning | `ReportIncorrectSecurityDetections` is `Disabled`, or any setting returns a value other than `Enabled`/`Disabled` |
| NotApplicable | The property was not returned. It isn't available in GCC, GCC High or DoD, and MicrosoftTeams versions before 6.7.0 don't expose `FileTypeCheck`/`UrlReputationCheck`. Reported as unassessed, never Pass |
| Fail (Error) | `Get-CsTeamsMessagingConfiguration` could not be called (module missing or insufficient permissions) |

## Recommendation

```powershell
Set-CsTeamsMessagingConfiguration -Identity Global -FileTypeCheck Enabled -UrlReputationCheck Enabled -ReportIncorrectSecurityDetections Enabled
```

Use the Teams admin center **Security detections** report (Analytics & reports > Protection reports) to review what these protections are catching.

`ContentBasedPhishingCheck` is also on this cmdlet but Microsoft marks it as not yet released, so this check doesn't assess it.

## Reference

- [Set-CsTeamsMessagingConfiguration](https://learn.microsoft.com/en-us/powershell/module/microsoftteams/set-csteamsmessagingconfiguration)
- [Weaponizable File Protection in Microsoft Teams](https://learn.microsoft.com/en-us/microsoftteams/weaponizable-file-protection-teams)
- [Malicious URL Protection in Microsoft Teams](https://learn.microsoft.com/en-us/microsoftteams/malicious-url-protection-teams)
- [Security detections report in Microsoft Teams](https://learn.microsoft.com/en-us/microsoftteams/teams-analytics-and-reports/security-detections-report)
