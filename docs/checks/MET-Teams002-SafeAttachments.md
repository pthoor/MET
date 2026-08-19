# MET-Teams002 - Safe Attachments for Teams

**Category:** Teams | **Severity:** High

## What it checks

Verifies the single global toggle that governs Safe Attachments protection for SharePoint, OneDrive, and Microsoft Teams: `Get-AtpPolicyForO365` → `EnableATPForSPOTeamsODB`.

Per Microsoft's own documentation ([Turn on Safe Attachments for SharePoint, OneDrive, and Microsoft Teams](https://learn.microsoft.com/en-us/defender-office-365/safe-attachments-for-spo-odfb-teams-configure)), this one tenant-wide setting is both how you turn the feature on *and* how you verify it - the article's own "how do you know this worked" section is `Get-AtpPolicyForO365 | Format-List EnableATPForSPOTeamsODB`. There is no separate per-policy sub-setting for Teams specifically: `Set-SafeAttachmentPolicy`'s full parameter set (`Action`, `AdminDisplayName`, `Enable`, `QuarantineTag`, `Redirect`, `RedirectAddress`) governs email-attachment scanning, a different mail-flow pipeline unrelated to SharePoint/OneDrive/Teams protection.

**Known limitation (fixed 2026-08-18):** earlier versions of this check additionally required a Safe Attachments policy with an `EnableSafeAttachmentsForTeams` property set to `$true`. That property does not exist on `Get-SafeAttachmentPolicy`/`Set-SafeAttachmentPolicy` - it was never a real, checkable setting, so every tenant with the global toggle on but no such (nonexistent) per-policy flag would fail this check regardless of actual configuration. The per-policy branch has been removed; the check now reflects Microsoft's actual, documented single-toggle model.

## Why it matters

Files shared via Teams channels and chats are a growing attack surface. Malicious files - macro-enabled Office documents, executables disguised as PDFs - can be shared by compromised internal accounts or external guests. Safe Attachments for SharePoint, OneDrive, and Teams scans files shared in those services before users can open, download, or share them.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | `EnableATPForSPOTeamsODB = $true` |
| Fail | `EnableATPForSPOTeamsODB = $false`, or the setting could not be retrieved |

## Recommendation

Run `Set-AtpPolicyForO365 -EnableATPForSPOTeamsODB $true`. Allow up to 30 minutes for the setting to take effect. Consider also `Set-SPOTenant -DisallowInfectedFileDownload $true` to block users from downloading files already identified as malicious (a separate, complementary SharePoint Online setting).

## Reference

- [Turn on Safe Attachments for SharePoint, OneDrive, and Microsoft Teams](https://learn.microsoft.com/en-us/defender-office-365/safe-attachments-for-spo-odfb-teams-configure)
