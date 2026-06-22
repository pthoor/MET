# MET-MDO010 — Priority Accounts

**Category:** MDO | **Severity:** Medium

## What it checks

- Whether any users have the **Priority Account** tag applied (via `Get-User -Filter "IsPriorityAccount -eq $true"`)
- Whether an anti-phishing policy with targeted user impersonation protection is scoped to cover those users

## Why it matters

Microsoft 365 Priority Accounts receive enhanced threat protection and differentiated security signals in the Defender portal. High-value targets — executives, board members, finance leads, IT admins — are disproportionately targeted in BEC and spear-phishing attacks. Tagging them as priority accounts ensures they appear in dedicated threat reports and can be targeted by stricter policies.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | Tags applied and a matching anti-phishing policy covers the tagged users |
| Warning | Tags not applied |
| Warning | Tags applied but no differentiated protection policy found |

## Recommendation

Tag high-value accounts in the Microsoft 365 admin center under **Active users → Priority account tag**. Then create or update an anti-phishing policy that targets those users with impersonation protection enabled.

## Reference

- [Manage and monitor priority accounts](https://aka.ms/priorityaccounts)
