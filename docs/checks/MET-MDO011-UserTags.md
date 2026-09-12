# MET-MDO011 - User Tags

**Category:** MDO | **Severity:** Low

## What it checks

MET cannot enumerate custom user tags or determine whether alert policies are tag-aware through its Exchange Online session. Exchange Online PowerShell has no cmdlet for custom-tag enumeration, and alert-policy queries require a Security and Compliance session.

Review both settings manually in the Microsoft 365 Defender portal: **Settings > Email & collaboration > User tags**. The built-in Priority account tag is a separate setting; it can be set through PowerShell with `Set-User -Identity <UPN> -VIP $true` and is assessed by MET-MDO010.

## Why it matters

User tags identify high-risk populations, such as board members and finance teams, in Defender investigations, reporting, and alerting. Reviewing both tag membership and tag-aware alert policies helps SecOps identify whether important populations receive the intended visibility and response.

## Result

| Result | Severity | Condition |
|---|---|---|
| Info | Low | Custom user tags and tag-aware alert policies cannot be assessed through MET's Exchange Online session; review them in the Defender portal. |

## Recommendation

Verify custom user tags and tag-aware alert policies manually in the Microsoft 365 Defender portal under **Settings > Email & collaboration > User tags**.

## Reference

- [User tags in Microsoft Defender for Office 365](https://aka.ms/mdo-usertags)
