# MET-MDO012 - Safe Documents

**Category:** MDO | **Severity:** Medium

## What it checks

Reviews the tenant-wide Safe Documents settings via `Get-AtpPolicyForO365`:

- **`EnableSafeDocs`** - whether Office files opened in Protected View on a Windows device are scanned by Defender for Office 365's cloud backend before a user is allowed to exit Protected View and edit the file
- **`AllowSafeDocsOpen`** - whether users are permitted to click through Protected View and open a file Safe Documents has already identified as malicious

This is a tenant-wide setting, not a per-policy or per-recipient one - there is no coverage matrix to resolve, unlike MET-MDO001/003/005-007/009.

## Why it matters

Protected View is a read-only sandbox Office applies to files from untrusted locations (email attachments, internet downloads, etc.), but it does not by itself scan file content - a user who trusts the sender can click "Enable Editing" and run whatever the file contains. Safe Documents adds a cloud-based scan on top of Protected View using the same detection engine as Safe Attachments, closing the gap for files that arrive through channels Safe Attachments doesn't cover (USB drives, SharePoint/OneDrive files opened locally, files from outside Exchange Online). `AllowSafeDocsOpen` is the more consequential of the two settings if left in its non-default state - Safe Documents can correctly flag a file as malicious and still let the user open it anyway, defeating the point of the scan.

Safe Documents requires Microsoft 365 A5/E5 or Microsoft 365 E5 Security licensing; on tenants without that licensing, `EnableSafeDocs` cannot be turned on and this check reports it as a gap regardless.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | `EnableSafeDocs` is enabled and `AllowSafeDocsOpen` is disabled |
| Fail | `EnableSafeDocs` is disabled, `AllowSafeDocsOpen` is enabled, or the global MDO policy could not be retrieved |

## Recommendation

```powershell
Set-AtpPolicyForO365 -EnableSafeDocs $true -AllowSafeDocsOpen $false
```

Requires Microsoft 365 A5/E5 or Microsoft 365 E5 Security licensing.

## Reference

- [Safe Documents in Microsoft 365 E5](https://learn.microsoft.com/en-us/defender-office-365/safe-docs-microsoft-365-security-atp)
