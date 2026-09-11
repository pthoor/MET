# MET-MDO010 - Priority Accounts

**Category:** MDO | **Severity:** High

## What it checks

This check emits two separately named results:

- **Priority Account Protection Toggle** retrieves `Get-EmailTenantSettings` and evaluates `EnablePriorityAccountProtection`, the tenant-wide MDO Plan 2 control.
- **Priority Account Tagging** retrieves tagged users with `Get-User -IsVIP -ResultSize Unlimited`.

The check does not read anti-phishing policies. If `Get-EmailTenantSettings` throws, it emits the toggle failure and returns before attempting the tagging retrieval.

## Why it matters

Priority accounts are high-value users, such as executives, finance leads, and administrators. The tenant-wide protection toggle supplies additional MDO heuristics for their mail patterns, while tags identify the accounts that should receive that differentiated treatment and reporting.

## Results

### Priority Account Protection Toggle

| Result | Severity | Condition |
|---|---|---|
| Pass | High | `EnablePriorityAccountProtection` is `$true`. |
| Fail | High | `EnablePriorityAccountProtection` is `$false`, or `Get-EmailTenantSettings` throws. A retrieval failure includes the error detail. |
| NotApplicable | High | `Get-EmailTenantSettings` returns no settings object, or it returns no `EnablePriorityAccountProtection` property/value. The state is unassessed, not assumed to be enabled. |

No settings object can be legitimate for a tenant without Microsoft Defender for Office 365 Plan 2 licensing; confirm licensing and retrieve the setting directly before treating that outcome as a configuration failure.

### Priority Account Tagging

| Result | Severity | Condition |
|---|---|---|
| Pass | Medium | `Get-User -IsVIP` returns one or more users. |
| Warning | Medium | `Get-User -IsVIP` returns zero users. |
| Fail | Medium | `Get-User -IsVIP` throws. The result includes the error detail. |

## Recommendation

Enable tenant-wide priority account protection in the Defender portal, and tag high-value accounts as Priority Accounts in the Microsoft 365 admin center. Confirm the toggle with:

```powershell
Get-EmailTenantSettings | Format-List EnablePriorityAccountProtection
```

## Reference

- [Turn on priority account protection](https://learn.microsoft.com/defender-office-365/priority-accounts-turn-on-priority-account-protection)
- [Manage priority accounts](https://learn.microsoft.com/microsoft-365/admin/setup/priority-accounts)
