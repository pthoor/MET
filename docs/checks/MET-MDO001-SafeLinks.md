# MET-MDO001 - Safe Links

**Category:** MDO | **Severity:** High

## What it checks

Resolves the effective Safe Links policy for every assessable mailbox, using
Microsoft's policy precedence, and then evaluates only policies that currently
affect recipients. The check reports one scored tenant result plus structured
policy coverage metadata in JSON and HTML.

Resolution order:

1. Strict preset
2. Standard preset
3. Enabled custom policies by ascending priority
4. Built-in protection

An enabled priority-0 custom rule with no Users, Groups, or Domains conditions is
shown as `Catch-all (no inclusion conditions)`. A higher-priority catch-all that
shadows a specialized custom policy produces a Warning and recommends moving the
catch-all below specialized policies. Overlap caused by presets or an intentional
specialized policy is informational.

For each effective policy, the check validates:

- `EnableSafeLinksForEmail` - URLs in email messages are scanned
- `EnableSafeLinksForOffice` - URLs in Office documents are scanned
- `TrackClicks` - user click data is recorded for investigation
- `EnableForInternalSenders` - protection applies to internal mail, not just external
- `ScanUrls` - real-time URL detonation is enabled
- `AllowClickThrough` - users are blocked from bypassing flagged URLs

## Why it matters

Safe Links rewrites and detonates URLs at click-time. Without it, phishing links that were clean at delivery time can detonate later (time-of-click detonation). The `AllowClickThrough` setting is a common misconfiguration - users can simply click through blocked warnings, negating the control.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | Every assessed mailbox receives an effective policy that meets the baseline |
| Fail | One or more mailboxes receive an effective policy below baseline |
| Warning | Mailboxes, rules, policies, groups, or complete precedence could not be resolved |
| NotApplicable | No assessable mailboxes were found |

Built-in protection is recognized as real basic protection, but it is below the
recommended Standard baseline when settings such as internal-sender protection
or blocked-URL click-through do not meet that baseline.

The policy inventory includes scope, state, priority, effective recipient count,
configuration status, current impact, and issues. Inactive, unassociated, and
fully shadowed policies remain visible. Shadowing by a custom catch-all produces
a Warning; other overlap is informational and does not cause a failure.

## Recommendation

Enable all Safe Links settings. For most tenants the simplest path is applying the **Standard** or **Strict** preset security policy. If custom policies are the intended model and recipients otherwise fall through to weak Built-in protection, add a compliant catch-all after all specialized custom policies.

## Reference

- [Set up Safe Links policies in Microsoft Defender for Office 365](https://aka.ms/mdo-safelinks)
