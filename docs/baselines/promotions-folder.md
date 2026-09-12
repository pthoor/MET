# Custom Policy Baseline - Promotions Folder

> **Warning:** The commands in this document mutate tenant configuration. They are optional guidance for administrators who deliberately want this mail-flow design, and are not executed by MET.

Microsoft's **Strict and Standard preset policies** apply a fixed, all-or-nothing configuration. The newer **Promotions folder** feature (currently in Preview) routes bulk email below the BCL threshold to a dedicated Promotions folder in supported Outlook clients - but **`BulkMovesEnabled` is Off in both preset policies and cannot be turned on within them**.

The only way to enable the Promotions folder is to move affected users out of the preset policies and onto **custom policies for every protection type**. Because preset policies bundle anti-spam, anti-phishing, anti-malware, Safe Links, and Safe Attachments together, removing users from a preset drops them back to the (weaker) default policies for all five areas unless you explicitly create custom equivalents.

The baseline below creates Strict-equivalent custom policies for all five protection types, then adds the Promotions folder toggle on top of the anti-spam policy.

> **Prerequisite:** Two things must both be in place for the Promotions folder to work:
> 1. A mail flow rule that stamps external bulk mail with the `X-MS-Exchange-Organization-BulkStamping: 1` header
> 2. `BulkMovesEnabled = On` in the anti-spam policy applied to those users

### Step 1 - Create the opt-in security group

```powershell
New-DistributionGroup `
    -Name                  'Promotions-OptIn' `
    -DisplayName           'Promotions Folder - Opt In' `
    -Alias                 'promotions-optin' `
    -Type                  Security `
    -MemberJoinRestriction Open
```

> `MemberJoinRestriction Open` lets users join or leave the group themselves to opt in or out. Change to `Closed` for admin-only control. To apply the Promotions folder to everyone, skip the group and replace `-SentToMemberOf 'Promotions-OptIn'` with `-RecipientDomainIs (Get-AcceptedDomain).DomainName` in each rule below.

### Step 2 - Create the bulk-stamping mail flow rule

```powershell
New-TransportRule `
    -Name               'Bulk Mail ID - Promotions Stamp' `
    -FromScope          NotInOrganization `
    -SentToMemberOf     'Promotions-OptIn' `
    -SetHeaderName      'X-MS-Exchange-Organization-BulkStamping' `
    -SetHeaderValue     '1' `
    -StopRuleProcessing $false `
    -Priority           0
```

### Step 3 - Custom anti-spam policy (Strict + Promotions folder)

```powershell
New-HostedContentFilterPolicy `
    -Name                             'Custom-Strict-AntiSpam' `
    -BulkThreshold                    5 `
    -BulkSpamAction                   Quarantine `
    -BulkQuarantineTag                DefaultFullAccessWithNotificationPolicy `
    -BulkMovesEnabled                 On `
    -SpamAction                       Quarantine `
    -SpamQuarantineTag                DefaultFullAccessWithNotificationPolicy `
    -HighConfidenceSpamAction         Quarantine `
    -HighConfidenceSpamQuarantineTag  DefaultFullAccessWithNotificationPolicy `
    -PhishSpamAction                  Quarantine `
    -PhishQuarantineTag               DefaultFullAccessWithNotificationPolicy `
    -HighConfidencePhishAction        Quarantine `
    -HighConfidencePhishQuarantineTag AdminOnlyAccessPolicy `
    -MarkAsSpamBulkMail               On `
    -SpamZapEnabled                   $true `
    -PhishZapEnabled                  $true `
    -QuarantineRetentionPeriod        30

New-HostedContentFilterRule `
    -Name                      'Custom-Strict-AntiSpam' `
    -HostedContentFilterPolicy 'Custom-Strict-AntiSpam' `
    -SentToMemberOf            'Promotions-OptIn' `
    -Priority                  0
```

### Step 4 - Custom anti-phishing policy (Strict equivalent)

```powershell
New-AntiPhishPolicy `
    -Name                                'Custom-Strict-AntiPhish' `
    -PhishThresholdLevel                 4 `
    -EnableSpoofIntelligence             $true `
    -AuthenticationFailAction            Quarantine `
    -SpoofQuarantineTag                  DefaultFullAccessWithNotificationPolicy `
    -EnableFirstContactSafetyTips        $true `
    -EnableMailboxIntelligence           $true `
    -EnableMailboxIntelligenceProtection $true `
    -MailboxIntelligenceProtectionAction Quarantine `
    -MailboxIntelligenceQuarantineTag    DefaultFullAccessWithNotificationPolicy `
    -EnableOrganizationDomainsProtection $true `
    -TargetedDomainProtectionAction      Quarantine `
    -TargetedDomainQuarantineTag         DefaultFullAccessWithNotificationPolicy `
    -EnableTargetedUserProtection        $true `
    -TargetedUserProtectionAction        Quarantine `
    -TargetedUserQuarantineTag           DefaultFullAccessWithNotificationPolicy `
    -EnableSimilarUsersSafetyTips        $true `
    -EnableSimilarDomainsSafetyTips      $true `
    -EnableUnusualCharactersSafetyTips   $true `
    -EnableUnauthenticatedSender         $true `
    -EnableViaTag                        $true `
    -HonorDmarcPolicy                    $true

New-AntiPhishRule `
    -Name            'Custom-Strict-AntiPhish' `
    -AntiPhishPolicy 'Custom-Strict-AntiPhish' `
    -SentToMemberOf  'Promotions-OptIn' `
    -Priority        0
```

> `EnableTargetedUserProtection` only activates once you populate `-TargetedUsersToProtect` with your high-value accounts. Pull them directly from your Priority Account tags and format them as required:
> ```powershell
> $vipUsers = Get-User -IsVIP -ResultSize Unlimited |
>     ForEach-Object { "$($_.DisplayName);$($_.WindowsEmailAddress)" }
> Set-AntiPhishPolicy -Identity 'Custom-Strict-AntiPhish' -TargetedUsersToProtect $vipUsers
> ```
> Max 350 entries. Mailbox intelligence impersonation (`EnableMailboxIntelligenceProtection`) covers all users automatically, so targeted user protection adds an extra layer specifically for your VIPs.

### Step 5 - Custom anti-malware policy (same settings as Standard and Strict)

When creating a malware filter policy via PowerShell without `-FileTypes`, the file type list starts **empty** even if `EnableFileFilter` is `$true`. The fix is to copy the list from the Default policy, which Microsoft maintains and updates over time.

```powershell
# Copy the current file type list from the Default policy
$defaultFileTypes = (Get-MalwareFilterPolicy -Identity Default).FileTypes

New-MalwareFilterPolicy `
    -Name             'Custom-Strict-AntiMalware' `
    -EnableFileFilter $true `
    -FileTypes        $defaultFileTypes `
    -FileTypeAction   Reject `
    -ZapEnabled       $true `
    -QuarantineTag    AdminOnlyAccessPolicy

New-MalwareFilterRule `
    -Name                'Custom-Strict-AntiMalware' `
    -MalwareFilterPolicy 'Custom-Strict-AntiMalware' `
    -SentToMemberOf      'Promotions-OptIn' `
    -Priority            0
```

> The Default policy contains Microsoft's maintained default file type list (`ace, ani, apk, app, appx, arj, bat, cab, cmd, com, deb, dex, dll, docm, elf, exe, hta, img, iso, jar, jnlp, kext, lha, lib, library, lnk, lzh, macho, msc, msi, msix, msp, mst, pif, ppa, ppam, reg, rev, scf, scr, sct, sys, uif, vb, vbe, vbs, vxd, wsc, wsf, wsh, xll, xz, z` and more). Copying from it instead of hardcoding ensures your custom policy stays in sync as Microsoft adds new types.

### Step 6 - Custom Safe Links policy (same settings as Standard and Strict)

```powershell
New-SafeLinksPolicy `
    -Name                     'Custom-Strict-SafeLinks' `
    -EnableSafeLinksForEmail  $true `
    -EnableSafeLinksForTeams  $true `
    -EnableSafeLinksForOffice $true `
    -ScanUrls                 $true `
    -DeliverMessageAfterScan  $true `
    -EnableForInternalSenders $true `
    -AllowClickThrough        $false `
    -TrackClicks              $true `
    -DisableUrlRewrite        $false

New-SafeLinksRule `
    -Name            'Custom-Strict-SafeLinks' `
    -SafeLinksPolicy 'Custom-Strict-SafeLinks' `
    -SentToMemberOf  'Promotions-OptIn' `
    -Priority        0
```

### Step 7 - Custom Safe Attachments policy (same settings as Standard and Strict)

```powershell
New-SafeAttachmentPolicy `
    -Name          'Custom-Strict-SafeAttachments' `
    -Enable        $true `
    -Action        Block `
    -QuarantineTag AdminOnlyAccessPolicy

New-SafeAttachmentRule `
    -Name                 'Custom-Strict-SafeAttachments' `
    -SafeAttachmentPolicy 'Custom-Strict-SafeAttachments' `
    -SentToMemberOf       'Promotions-OptIn' `
    -Priority             0
```

### Step 8 - Exclude the opt-in group from preset policies

Users in `Promotions-OptIn` must be excluded from every Standard or Strict preset scope that currently covers them, otherwise the preset wins the priority order and the custom policies never apply. Presets have two rule sets: EOP (anti-spam, anti-phish, anti-malware) and ATP (Safe Links, Safe Attachments).

Preserve every existing preset exclusion when adding the opt-in group. Passing only `Promotions-OptIn` to `-ExceptIfSentToMemberOf` replaces that multi-valued collection. The loop below reads each current collection, appends the group, removes empty or duplicate entries, and writes the merged values back, following Microsoft's [guidance for modifying multivalued Exchange properties](https://learn.microsoft.com/exchange/modifying-multivalued-properties-exchange-2013-help).

```powershell
# View current preset scope
Get-EOPProtectionPolicyRule | Format-List Name, SentToMemberOf, ExceptIfSentToMemberOf
Get-ATPProtectionPolicyRule | Format-List Name, SentToMemberOf, ExceptIfSentToMemberOf

$group = 'Promotions-OptIn'
$presetNames = @(
    'Strict Preset Security Policy'
    # Add 'Standard Preset Security Policy' here if these users are also covered by it.
)

foreach ($presetName in $presetNames) {
    $eopRule = Get-EOPProtectionPolicyRule -Identity $presetName
    $eopExceptions = @(
        $eopRule.ExceptIfSentToMemberOf | ForEach-Object { [string] $_ }
        $group
    ) | Where-Object { $_ } | Sort-Object -Unique

    Set-EOPProtectionPolicyRule `
        -Identity               $presetName `
        -ExceptIfSentToMemberOf $eopExceptions

    $atpRule = Get-ATPProtectionPolicyRule -Identity $presetName
    $atpExceptions = @(
        $atpRule.ExceptIfSentToMemberOf | ForEach-Object { [string] $_ }
        $group
    ) | Where-Object { $_ } | Sort-Object -Unique

    Set-ATPProtectionPolicyRule `
        -Identity               $presetName `
        -ExceptIfSentToMemberOf $atpExceptions
}
```

### How the Promotions folder feature works after setup

| Bulk mail BCL | What happens |
|---|---|
| BCL ≥ 5 (meets/exceeds threshold) | Quarantined (`BulkSpamAction = Quarantine`) |
| BCL < 5, stamped by mail flow rule | Delivered to **Promotions** folder |
| Sender is in user's Safe Senders list | Delivered to Inbox (bypasses Promotions) |
| Sender is internal / accepted domain | Not stamped by the rule - delivered normally |

Microsoft 365 learns from user behaviour in the Promotions folder (moving messages in or out) and applies those preferences automatically to future messages.

### MET checks that assess this baseline

| Check | What it verifies |
|---|---|
| MET-MDO001 | Safe Links enabled, internal senders covered, click-through blocked |
| MET-MDO002 | Safe Attachments action is Block or DynamicDelivery |
| MET-MDO003 | Anti-phish: mailbox intelligence, impersonation, safety tips |
| MET-MDO004 | Anti-spoofing action and DMARC honour settings |
| MET-MDO005 | Anti-malware: file filter, ZAP, quarantine tag |
| MET-MDO006 | BCL threshold, bulk action, spam/phish actions, ZAP |
| MET-MDO008 | Preset policy coverage - opt-in users on custom policies will show as uncovered; this is expected and accepted for this scenario |
| MET-MDO009 | ZAP enabled in all active policies including the custom ones |
| MET-EXO007 | Transport rule audit - bulk-stamping rule listed as informational |
| MET-EXO008 | Quarantine retention ≥ 30 days in the custom anti-spam policy |
| MET-EXO009 | Quarantine tag permissiveness for Malware/High-Confidence Phish across all custom policies |
