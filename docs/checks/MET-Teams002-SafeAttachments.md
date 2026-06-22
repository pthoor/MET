# MET-Teams002 — Safe Attachments for Teams

**Category:** Teams | **Severity:** High

## What it checks

Verifies that at least one Safe Attachments policy has `EnableSafeAttachmentsForTeams` set to `true`.

## Why it matters

Files shared via Teams channels and chats are a growing attack surface. Malicious files — macro-enabled Office documents, executables disguised as PDFs — can be shared by compromised internal accounts or external guests. Safe Attachments for Teams scans files shared in Teams before users can open them.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | At least one policy has `EnableSafeAttachmentsForTeams = true` |
| Fail | No policies, or no policy has Teams enabled |

## Recommendation

Enable `EnableSafeAttachmentsForTeams` in a Safe Attachments policy that covers all Teams users.

## Reference

- [Safe Attachments for SharePoint, OneDrive, and Teams](https://aka.ms/mdo-safeattachments-teams)
