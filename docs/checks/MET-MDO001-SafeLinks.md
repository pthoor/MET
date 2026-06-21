# MET-MDO001 — Safe Links

**Category:** MDO | **Severity:** High

## What it checks

Verifies that Safe Links policies are configured to protect email and Office apps:

- `EnableSafeLinksForEmail` — URLs in email messages are scanned
- `EnableSafeLinksForOffice` — URLs in Office documents are scanned
- `TrackClicks` — user click data is recorded for investigation
- `EnableForInternalSenders` — protection applies to internal mail, not just external
- `ScanUrls` — real-time URL detonation is enabled
- `AllowClickThrough` — users are blocked from bypassing flagged URLs

## Why it matters

Safe Links rewrites and detonates URLs at click-time. Without it, phishing links that were clean at delivery time can detonate later (time-of-click detonation). The `AllowClickThrough` setting is a common misconfiguration — users can simply click through blocked warnings, negating the control.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | All six settings are in the correct state |
| Fail | One or more settings are misconfigured |
| Fail | No Safe Links policies exist |

## Recommendation

Enable all Safe Links settings. For most tenants the simplest path is applying the **Standard** or **Strict** preset security policy, which sets all Safe Links controls to their recommended values.

## Reference

- [Set up Safe Links policies in Microsoft Defender for Office 365](https://aka.ms/mdo-safelinks)
