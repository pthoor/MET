# MET-Teams015 - Teams Email Integration

**Category:** Teams | **Severity:** Medium

## What it checks

Reads `AllowEmailIntoChannel` from `Get-CsTeamsClientConfiguration` to determine whether Teams channels in the tenant can be issued an email address that accepts mail from outside the organisation.

## Why it matters

When channel email integration is enabled, any Teams channel can be given an `@<tenant>.teams.ms` address, and that address accepts mail from external senders. Mail sent to it is delivered into the channel conversation rather than to a mailbox.

That distinction is the whole risk:

1. The message never traverses the mailbox-delivery path that the rest of this module assesses. Exchange transport rules and mailbox-level policy do not apply to it.
2. The payload arrives in a space colleagues implicitly trust as internal - a channel post looks like it came from a teammate, not from an unknown external sender.
3. Together, those two facts make channel email an attractive delivery route for a phishing payload or a social-engineering lure that would have been filtered, tagged, or quarantined on the mail path.

This is a legitimate and widely-used collaboration feature, so an enabled setting is reported as a Warning rather than a hard Fail. The finding is that it constitutes an unmonitored ingress path, not that the feature is inherently a misconfiguration.

Teams also supports a per-team restriction that limits which senders may mail a channel to a named list of accepted domains. That middle ground is usually the right answer where teams genuinely depend on the feature, rather than switching it off outright.

Note that disabling the tenant-wide setting does not revoke channel email addresses that have already been issued, so previously-issued addresses need to be reviewed separately.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | `AllowEmailIntoChannel` is `$false` - channels cannot be issued an email address |
| Warning | `AllowEmailIntoChannel` is `$true` - channel email is an ingress path that bypasses mailbox delivery |
| Warning | `AllowEmailIntoChannel` is absent or null - the setting could not be confirmed and must be checked manually |
| Fail (Error) | Unable to retrieve the Teams client configuration (MicrosoftTeams module not loaded, or insufficient permissions) |

## Recommendation

Disable channel email integration tenant-wide:

```powershell
Set-CsTeamsClientConfiguration -Identity Global -AllowEmailIntoChannel $false
```

Where teams genuinely depend on the feature, leave it enabled and instead:

1. Restrict inbound senders per team to a named accepted-domain list via the channel's email address settings, so arbitrary external senders cannot post into a channel.
2. Review which channels currently have an email address issued, and remove addresses that are no longer needed.
3. Treat any channel with an open (unrestricted) address as an externally-reachable ingress point when scoping monitoring and user awareness training.

Because addresses already issued survive the setting being disabled, run step 2 regardless of which direction you take on the tenant-wide setting.

## Reference

- [Set-CsTeamsClientConfiguration](https://learn.microsoft.com/en-us/powershell/module/microsoftteams/set-csteamsclientconfiguration)
- [Get-CsTeamsClientConfiguration](https://learn.microsoft.com/en-us/powershell/module/microsoftteams/get-csteamsclientconfiguration)
- [Send an email to a channel in Microsoft Teams](https://learn.microsoft.com/en-us/microsoftteams/manage-email-integration)
