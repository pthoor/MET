# MET-Teams008 - App Permission Policy Exposure

**Category:** Teams | **Severity:** Medium

## What it checks

Reviews every Teams app permission policy returned by `Get-CsTeamsAppPermissionPolicy` (the `Global` policy plus any custom policies) and inspects three properties on each: `GlobalCatalogAppsType`, `DefaultCatalogAppsType`, and `PrivateCatalogAppsType`. These control whether apps from the Microsoft catalog, the Microsoft-approved catalog, and privately/org-published apps respectively can be installed without restriction.

A value of `AllowedAppList` (an explicit, reviewed allow-list) or `BlockedAppList` (an explicit block-list) is treated as an intentional, restrictive configuration. Any other value is treated as an unrestricted "allow everything" configuration and flagged.

This check is **read-only awareness only**. It calls only the `Get-` cmdlet and never attempts to modify a policy - Microsoft's guidance is that Teams app permission policies must be created and modified in the Teams admin center (Teams apps > Permission policies), not via PowerShell `Set-`/`New-` cmdlets.

## Why it matters

Third-party Teams apps request delegated Microsoft Graph permissions (mail, files, calendar, chat) when a user consents to install them. When an app permission policy leaves a catalog unrestricted, any user can install any published app without review, exposing the tenant to:

- **OAuth consent phishing** - a malicious or look-alike app tricks a user into granting delegated Graph permissions
- **Supply-chain risk** - a legitimate-looking app is later compromised or sold, and its existing consent grants persist
- **Unreviewed data access** - apps with broad Graph scopes reading mail, files, or chat content without security team visibility

Restricting each catalog to an explicit allow-list (or block-list, for organizations that prefer default-allow with named exceptions) ensures app installation goes through a deliberate review process rather than defaulting to open.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | All policies have `GlobalCatalogAppsType`, `DefaultCatalogAppsType`, and `PrivateCatalogAppsType` set to `AllowedAppList` or `BlockedAppList` |
| Warning | One or more policies has at least one of those three properties set to any other value, or the policies could not be retrieved |

## Recommendation

Third-party Teams apps carry delegated Graph permissions and are a growing OAuth-consent-phishing and supply-chain vector. Configure app permission policies in the Teams admin center (Teams apps > Permission policies) to use an explicit allowed-app list or blocked-app list rather than leaving any catalog unrestricted. Policy changes must be made in the admin center, not via PowerShell `Set-`/`New-` cmdlets.

## Known limitation

Microsoft's guidance states that `Get`/`Set`/`Remove-CsTeamsAppPermissionPolicy` are only applicable for tenants that have not migrated to App Centric Management (ACM) or Unified App Management (UAM). On a migrated tenant the cmdlet may still return policy data, but that policy no longer actually governs app access - this check can then report a misleadingly clean Pass. There is currently no confirmed cmdlet or Graph property to detect ACM/UAM migration status, so this check cannot detect that condition itself; both the Pass and Warning results carry a recommendation to verify current app governance in the Teams admin center directly.

## Reference

- [Manage app permission policies in Microsoft Teams](https://learn.microsoft.com/en-us/microsoftteams/teams-app-permission-policies)
