# MET-EXO021 - Mailbox Audit Logging

**Category:** EXO | **Severity:** Medium

## What it checks

Reads the `AuditDisabled` property from the organization configuration (`Get-OrganizationConfig`) to determine whether mailbox audit logging is switched off tenant-wide.

The property's sense is inverted relative to the result:

- `AuditDisabled = $true` means mailbox auditing is **off** organization-wide - reported as a Fail
- `AuditDisabled = $false` means mailbox auditing is **on** - reported as a Pass
- The property being absent is reported as a Pass, because mailbox auditing is on by default on the platform, but the finding states explicitly that the value was assumed from that default rather than observed on this tenant

## Why it matters

Mailbox audit records are the evidence base that every business email compromise investigation depends on. Without them there is no way to reconstruct what a compromised account actually did inside the mailbox: which messages it read, which folders it moved mail into, what it exported, and which items it deleted to cover its tracks. Sign-in logs establish that an intruder got in; only mailbox audit records establish what they took.

The critical property of this control is that it cannot be applied retroactively. Audit records only exist for activity that occurred while auditing was on - turning it on after an incident is discovered produces nothing for the period that matters. A tenant that finds this setting disabled during an investigation has already permanently lost the history it needs to scope the breach, notify affected parties accurately, or answer a regulator's question about what data was accessed.

Because the loss is silent and irreversible, this is worth verifying periodically rather than assuming, particularly in tenants where the setting may have been changed years ago for performance or licensing reasons that no longer apply.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | `AuditDisabled` is `$false` - mailbox auditing is enabled organization-wide |
| Pass | `AuditDisabled` is absent - state assumed from the platform default (auditing on), noted in the finding as assumed rather than observed |
| Fail | `AuditDisabled` is `$true` - mailbox auditing is turned off organization-wide |
| Fail (Error) | Unable to retrieve the organization configuration (permissions issue) |

## Recommendation

Re-enable mailbox audit logging for the organization:

```powershell
Set-OrganizationConfig -AuditDisabled $false
```

Then confirm that per-mailbox auditing is actually on, since the organization-wide switch does not by itself guarantee every mailbox is being audited:

```powershell
Get-Mailbox -ResultSize Unlimited | Format-List UserPrincipalName, AuditEnabled
```

Records only begin accruing from the moment auditing is enabled, so treat this as a control to verify on a schedule rather than a one-time fix.

## Reference

- [Manage mailbox auditing](https://learn.microsoft.com/en-us/purview/audit-mailboxes)
- [Set-OrganizationConfig](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-organizationconfig)
