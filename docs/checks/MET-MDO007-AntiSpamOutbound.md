# MET-MDO007 - Anti-Spam Outbound

**Category:** MDO | **Severity:** Medium

## What it checks

Resolves the effective outbound anti-spam policy for each assessable sender using custom rule priority, sender/group/domain conditions, exceptions, and default fallback. It then verifies:

- `AutoForwardingMode` - `Off` is the explicit recommended setting; `On` fails and `Automatic` produces a review warning
- `ActionWhenThresholdReached` - Standard recommends `BlockUser`

`NotifyOutboundSpamRecipients` is not required. Microsoft recommends the built-in restricted-user alert policy for administrator notifications and documents the outbound policy notification setting as disabled in its recommended configurations.

The report warns when a higher-priority outbound catch-all shadows specialized sender policies. If a catch-all is needed, it should have the lowest custom precedence so narrower sender, group, or domain policies remain effective.

## Why it matters

Auto-forwarding rules are a common post-compromise technique for exfiltrating mail to attacker-controlled addresses. Disabling auto-forwarding at the policy level provides a tenant-wide backstop against compromised accounts silently forwarding all received mail. Outbound spam threshold actions protect the tenant's sending reputation.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | Every sender receives an effective policy with forwarding explicitly off and the Standard restriction action |
| Fail | One or more effective policies enable forwarding or use a restriction action below the Standard baseline |
| Warning | Forwarding is system-controlled, or effective coverage is incomplete |
| NotApplicable | No assessable senders were found |

## Recommendation

Set `AutoForwardingMode` to `Off` and the sending limit action to `BlockUser`. Verify the `User restricted from sending email` alert policy separately for administrator notification coverage.

## Reference

- [Outbound spam protection in EOP](https://aka.ms/mdo-outboundspam)
- [Microsoft recommended threat policy settings](https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365#outbound-spam-policy-settings)
