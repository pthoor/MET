# MET-EXO015 — External Sender Warning Tag

**Category:** EXO | **Severity:** Medium

## What it checks

Verifies that the External Sender Warning Tag feature is enabled in Outlook. This feature causes Outlook (desktop, web, mobile) to display a native "External" indicator in the sender area of messages originating from outside the organization, optionally with a list of allowed senders/domains that bypass the tag.

## Why it matters

The External Sender Warning Tag is a **user-facing cosmetic control**, not a filter — it does not block or quarantine mail. Its value lies in human detection. End users are the last line of defense against Business Email Compromise (BEC), lookalike-domain, and spoofing attacks. Even when technical filters (SPF, DMARC, anti-spoofing) are properly configured, clever attackers can sometimes craft mail that passes all filters. A visible "External" label trains users to treat unexpected messages from outside the org with skepticism and is especially effective at catching attacks that impersonate internal domains or lookalike domains the attacker controls.

When the tag is disabled, users see no visual distinction between mail from coworkers and mail from untrusted external senders, making them more vulnerable to social engineering.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | External sender tagging is enabled |
| Warning | External sender tagging is disabled |

## Recommendation

Enable the External Sender Warning Tag immediately:

```powershell
Set-ExternalInOutlook -Enabled $true
```

This command is tenant-wide and takes 24–48 hours to propagate to all Outlook clients (desktop, web, mobile). No licensing is required. Optionally, define an allow list of trusted external senders/domains to suppress the tag for known partners (e.g., `Set-ExternalInOutlook -Enabled $true -AllowList 'partner@external.com', '*.trustedvendor.com'`), though this should be used sparingly — the tag's protective value diminishes when users grow accustomed to ignoring it for large allow lists.

## Reference

- [External Sender Warning Tag in Outlook](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-externalinoutlook)
- [Combating email spoofing](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-spoofing-protection)
- [Business Email Compromise trends](https://www.microsoft.com/en-us/security/blog/)
