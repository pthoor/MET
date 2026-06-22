# MET — Security Posture Scanner for MDO, EXO and Teams

Open-source PowerShell module for assessing the security posture of a Microsoft 365 tenant across Microsoft Defender for Office 365 (MDO), Exchange Online Protection (EOP), and Microsoft Teams threat protection.

---

## Dependencies

### PowerShell

| Requirement | Detail |
|---|---|
| **Minimum** | PowerShell **7.4** |
| **Tested on** | PowerShell **7.4**, **7.6** |
| **Platform** | Windows (full support). Linux/macOS: all checks except DMARC (EXO001) and SPF (EXO003), which require `Resolve-DnsName` — a Windows-only cmdlet. |

### Required modules

These must be installed before you can import MET or run any checks.

```powershell
Install-Module ExchangeOnlineManagement          -MinimumVersion 3.0.0 -Scope CurrentUser
Install-Module Microsoft.Graph.Identity.SignIns  -MinimumVersion 2.0.0 -Scope CurrentUser
Install-Module Microsoft.Graph.Groups            -MinimumVersion 2.0.0 -Scope CurrentUser
```

### Optional modules

Required only for Teams checks (Teams001–003). If not installed, `Connect-METSession` logs a warning and Teams checks fail gracefully with an explanatory error in the result object.

```powershell
Install-Module MicrosoftTeams -MinimumVersion 6.0.0 -Scope CurrentUser
```

### Required M365 permissions

MET is **read-only** — it never modifies tenant configuration. Follow the principle of least privilege: grant only what is listed here.

#### Exchange Online

| Role / permission | Why it is needed |
|---|---|
| **Security Reader** (EXO role group) | Read all MDO/EOP policy cmdlets: `Get-SafeLinksPolicy`, `Get-AntiPhishPolicy`, `Get-MalwareFilterPolicy`, `Get-HostedContentFilterPolicy`, `Get-QuarantinePolicy`, `Get-TenantAllowBlockListItems`, `Get-ReportSubmissionPolicy`, `Get-DkimSigningConfig`, `Get-TransportRule`, `Get-AtpPolicyForO365`, `Get-ProtectionAlert`, `Get-Tag` |
| **View-Only Recipients** (EXO management role) | Enumerate mailboxes and distribution group membership (`Get-EXOMailbox`, `Get-DistributionGroupMember`, `Get-User`, `Get-AcceptedDomain`, `Get-EOPProtectionPolicyRule`) |

> The **Security Reader** EXO role group already includes View-Only Configuration, so you only need to add **View-Only Recipients** on top of it. Do _not_ use Organization Management or Security Administrator — those grant write access.

#### Microsoft Graph (Application permissions)

These are requested by `Connect-METSession`. All are **read-only**.

| Permission | Why it is needed |
|---|---|
| `Organization.Read.All` | Read tenant name and domain list |
| `Group.Read.All` | Resolve group membership for preset policy coverage (MDO008) |

> If you are running only Exchange/Teams checks and want to skip Graph entirely, use `Connect-METSession -SkipGraph`.

#### Microsoft Teams

| Role | Why it is needed |
|---|---|
| **Global Reader** (Microsoft Entra role) | Read Teams federation and meeting policy settings via `Get-CsTenantFederationConfiguration` and `Get-CsTeamsMeetingPolicy` |

> **Do not use Teams Administrator** — that role grants write access to Teams configuration. Global Reader is sufficient for all current Teams checks. If you do not run Teams checks, use `Connect-METSession -SkipTeams`.

#### Assigning roles to a service principal (unattended / CI)

```powershell
# 1. Create the service principal in Exchange Online
New-ServicePrincipal -AppId $appId -ServiceId $spObjectId -DisplayName 'MET CI'

# 2. Add it to the Security Reader role group
Add-RoleGroupMember -Identity 'Security Reader' -Member 'MET CI'

# 3. Grant the View-Only Recipients management role directly
New-ManagementRoleAssignment -Role 'View-Only Recipients' -App $appId

# 4. Grant Graph Application permissions in Entra (portal or CLI)
#    Organization.Read.All, Group.Read.All

# 5. Assign Global Reader in Entra for Teams access
#    Microsoft Entra admin center → Roles → Global Reader → Add assignment → select the service principal
```

> For the Graph and Teams roles, the service principal needs an **App Registration** in Entra ID. Graph Application permissions must be **admin-consented**.

---

## Install

From the PowerShell Gallery (once published):

```powershell
Install-Module -Name MET -Repository PSGallery -Scope CurrentUser
```

Or clone and import locally:

```powershell
git clone https://github.com/pthoor/MET
Import-Module ./MET/MET.psd1
```

---

## Quickstart

```powershell
# 1. Install dependencies (first time only)
Install-Module ExchangeOnlineManagement, Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Groups -Scope CurrentUser

# 2. Connect (interactive browser login)
Connect-METSession

# 3. Run all checks
$results = Invoke-METTriage

# 4. View in console
$results | Get-METReport

# 5. Open interactive HTML report in your browser
$results | Get-METReport -Format HTML -OutputPath ./assessments

# 6. Export JSON (for SIEM / CI gates)
$results | Get-METReport -Format JSON -OutputPath ./assessments
```

### Service Principal (unattended / CI)

```powershell
Connect-METSession `
    -AppId               $appId `
    -TenantId            $tenantId `
    -CertificateThumbprint $thumb

$results = Invoke-METTriage
$results | Get-METReport -Format JSON -OutputPath ./assessments
```

### Scoped runs

```powershell
# MDO checks only
Invoke-METTriage -Category MDO

# EXO checks only
Invoke-METTriage -Category EXO

# Teams checks only (requires MicrosoftTeams module)
Invoke-METTriage -Category Teams

# Specific check IDs
Invoke-METTriage -CheckId MET-MDO001, MET-EXO001

# All checks except transport rule audit (informational)
Invoke-METTriage -ExcludeCheckId MET-EXO007

# MSSP — run against a delegated tenant
Invoke-METTriage -DelegatedOrganization contoso.onmicrosoft.com
```

### Skip a service

```powershell
# Skip Teams connection (if MicrosoftTeams module is not installed)
Connect-METSession -SkipTeams

# Skip Graph (if only running EXO checks that don't need Graph)
Connect-METSession -SkipGraph
```

### Exchange sign-in troubleshooting

```powershell
# If interactive sign-in hangs, use device code flow
Connect-METSession -SkipGraph -SkipTeams -UseDeviceAuthentication -Verbose

# If your environment has WAM issues, disable WAM for EXO sign-in
Connect-METSession -SkipGraph -SkipTeams -DisableWAM -Verbose

# Optional: pre-select the account
Connect-METSession -UserPrincipalName admin@contoso.com -Verbose
```

---

## Custom Policy Baseline — Promotions Folder

Microsoft's **Strict and Standard preset policies** apply a fixed, all-or-nothing configuration. The newer **Promotions folder** feature (currently in Preview) routes bulk email below the BCL threshold to a dedicated Promotions folder in supported Outlook clients — but **`BulkMovesEnabled` is Off in both preset policies and cannot be turned on within them**.

The only way to enable the Promotions folder is to move affected users out of the preset policies and onto **custom policies for every protection type**. Because preset policies bundle anti-spam, anti-phishing, anti-malware, Safe Links, and Safe Attachments together, removing users from a preset drops them back to the (weaker) default policies for all five areas unless you explicitly create custom equivalents.

The baseline below creates Strict-equivalent custom policies for all five protection types, then adds the Promotions folder toggle on top of the anti-spam policy.

> **Prerequisite:** Two things must both be in place for the Promotions folder to work:
> 1. A mail flow rule that stamps external bulk mail with the `X-MS-Exchange-Organization-BulkStamping: 1` header
> 2. `BulkMovesEnabled = On` in the anti-spam policy applied to those users

### Step 1 — Create the opt-in security group

```powershell
New-DistributionGroup `
    -Name                  'Promotions-OptIn' `
    -DisplayName           'Promotions Folder - Opt In' `
    -Alias                 'promotions-optin' `
    -Type                  Security `
    -MemberJoinRestriction Open
```

> `MemberJoinRestriction Open` lets users join or leave the group themselves to opt in or out. Change to `Closed` for admin-only control. To apply the Promotions folder to everyone, skip the group and replace `-SentToMemberOf 'Promotions-OptIn'` with `-RecipientDomainIs (Get-AcceptedDomain).DomainName` in each rule below.

### Step 2 — Create the bulk-stamping mail flow rule

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

### Step 3 — Custom anti-spam policy (Strict + Promotions folder)

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

### Step 4 — Custom anti-phishing policy (Strict equivalent)

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

### Step 5 — Custom anti-malware policy (same settings as Standard and Strict)

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

### Step 6 — Custom Safe Links policy (same settings as Standard and Strict)

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

### Step 7 — Custom Safe Attachments policy (same settings as Standard and Strict)

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

### Step 8 — Exclude the opt-in group from preset policies

Users in `Promotions-OptIn` must be excluded from both the Standard and Strict preset scope, otherwise the preset wins the priority order and the custom policies never apply. Presets have two rule sets: EOP (anti-spam, anti-phish, anti-malware) and ATP (Safe Links, Safe Attachments).

```powershell
# View current preset scope
Get-EOPProtectionPolicyRule | Format-List Name, SentToMemberOf, ExceptIfSentToMemberOf
Get-ATPProtectionPolicyRule | Format-List Name, SentToMemberOf, ExceptIfSentToMemberOf

# Exclude from Strict preset — EOP rules
Set-EOPProtectionPolicyRule `
    -Identity               'Strict Preset Security Policy' `
    -ExceptIfSentToMemberOf 'Promotions-OptIn'

# Exclude from Strict preset — ATP rules (Safe Links + Safe Attachments)
Set-ATPProtectionPolicyRule `
    -Identity               'Strict Preset Security Policy' `
    -ExceptIfSentToMemberOf 'Promotions-OptIn'

# Repeat for Standard preset if users are also covered by it
Set-EOPProtectionPolicyRule `
    -Identity               'Standard Preset Security Policy' `
    -ExceptIfSentToMemberOf 'Promotions-OptIn'

Set-ATPProtectionPolicyRule `
    -Identity               'Standard Preset Security Policy' `
    -ExceptIfSentToMemberOf 'Promotions-OptIn'
```

### How the Promotions folder feature works after setup

| Bulk mail BCL | What happens |
|---|---|
| BCL ≥ 5 (meets/exceeds threshold) | Quarantined (`BulkSpamAction = Quarantine`) |
| BCL < 5, stamped by mail flow rule | Delivered to **Promotions** folder |
| Sender is in user's Safe Senders list | Delivered to Inbox (bypasses Promotions) |
| Sender is internal / accepted domain | Not stamped by the rule — delivered normally |

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
| MET-MDO008 | Preset policy coverage — opt-in users on custom policies will show as uncovered; this is expected and accepted for this scenario |
| MET-MDO009 | ZAP enabled in all active policies including the custom ones |
| MET-EXO007 | Transport rule audit — bulk-stamping rule listed as informational |
| MET-EXO008 | Quarantine retention ≥ 30 days in the custom anti-spam policy |
| MET-EXO009 | Quarantine tag permissiveness for each verdict across all custom policies |

---

## Check Inventory

### MDO — Microsoft Defender for Office 365

| ID | Name | Severity | What it assesses |
|---|---|---|---|
| MET-MDO001 | Safe Links | High | Email + Office app URL scanning, click-through, internal senders |
| MET-MDO002 | Safe Attachments | High | Policy enabled, action is Block or DynamicDelivery |
| MET-MDO003 | Anti-Phishing | High | Mailbox intelligence, impersonation protection, safety tips |
| MET-MDO004 | Anti-Spoofing | High | Spoof intelligence, DMARC honor, auth failure action |
| MET-MDO005 | Anti-Malware | High | ZAP, common attachment filter, admin notifications |
| MET-MDO006 | Anti-Spam Inbound | Medium | Spam/phish actions, high-confidence thresholds, BCL |
| MET-MDO007 | Anti-Spam Outbound | Medium | Auto-forward disabled, send limit action, admin alerts |
| MET-MDO008 | Preset Policy Coverage | Medium | % of mailboxes covered by Standard or Strict preset |
| MET-MDO009 | Zero-Hour Auto Purge | High | ZAP enabled for spam and phishing in all policies |
| MET-MDO010 | Priority Accounts | Medium | Priority Account tag usage + differentiated protection policy |
| MET-MDO011 | User Tags | Low | Custom tags defined + alert policies referencing them |
| MET-MDO012 | Safe Documents | Medium | EnableSafeDocs enabled; AllowSafeDocsOpen disabled |

### EXO — Exchange Online / Email Authentication

| ID | Name | Severity | What it assesses |
|---|---|---|---|
| MET-EXO001 | DMARC | High | Record present, policy quarantine/reject, rua reporting |
| MET-EXO002 | DKIM | High | Signing enabled, key ≥ 2048 bit, CNAME status valid |
| MET-EXO003 | SPF | High | Record present, -all enforcement, ≤ 10 DNS lookups |
| MET-EXO004 | Quarantine Policies | Medium | End-user permissions, retention ≥ 15 days, phish self-release |
| MET-EXO005 | Tenant Allow/Block List | Low | Stale allows (>90 days), wildcard allows, allow/block ratio |
| MET-EXO006 | Submission Policy | Medium | Report-to-Microsoft on, custom submission mailbox configured |
| MET-EXO007 | Transport Rule Audit | Medium | Rules bypassing spam filter (SCL=-1) or disabling Safe Links |
| MET-EXO008 | Quarantine Retention | Medium | QuarantineRetentionPeriod ≥ 30 days in all anti-spam policies |
| MET-EXO009 | Quarantine Policy Verdict Alignment | Medium | Quarantine tags not too permissive for high-risk verdicts (malware, high-confidence phish) |

### Teams — Microsoft Teams Threat Protection

| ID | Name | Severity | What it assesses |
|---|---|---|---|
| MET-Teams001 | Safe Links for Teams | High | EnableSafeLinksForTeams in at least one policy |
| MET-Teams002 | Safe Attachments for Teams | High | EnableSafeAttachmentsForTeams in at least one policy |
| MET-Teams003 | Meeting Protection | Medium | Anonymous join, lobby bypass (AutoAdmittedUsers), federation |
| MET-Teams004 | ZAP for Teams | High | TeamsProtectionPolicy ZAP enabled; malware and high-confidence phish quarantine tags set to AdminOnlyAccessPolicy |
| MET-Teams005 | Teams User Reporting | Low | ReportTeamsMsgEnabled in report submission policy; AllowSecurityEndUserReporting in Teams messaging policy |

---

## Scoring

| Severity | Weight |
|---|---|
| Critical | 40 |
| High | 20 |
| Medium | 10 |
| Low | 5 |
| Informational | 0 |

**Per-check score**: Pass = 100 · Warning = 50 · Fail = 0

**Overall posture index**: weighted average across all applicable (non-NotApplicable, non-accepted) checks, scaled 0–100.

**Bands**: 0–39 Critical · 40–59 Poor · 60–79 Fair · 80–94 Good · 95–100 Excellent

---

## Output formats

| Format | Command | Notes |
|---|---|---|
| Console | `Get-METReport` | Coloured summary + issues table |
| JSON | `Get-METReport -Format JSON -OutputPath ./assessments` | Machine-readable; suitable for SIEM / CI |
| HTML | `Get-METReport -Format HTML -OutputPath ./assessments` | Self-contained; auto-opens in browser |
| All | `Get-METReport -Format All -OutputPath ./assessments` | Writes both JSON and HTML to a per-run subfolder |

The HTML report is a **single self-contained file** — all CSS and JavaScript are inlined, no CDN or internet connection required to view it.

When `-OutputPath` is provided, MET now creates a timestamped run folder and writes reports inside it (for example `./assessments/20260602-102530-contoso_onmicrosoft.com/`).

---

## Development

### Running tests

```powershell
Install-Module Pester -MinimumVersion 5.0.0 -Scope CurrentUser

$config = New-PesterConfiguration
$config.Run.Path = './Tests/Unit'
$config.Output.Verbosity = 'Detailed'
Invoke-Pester -Configuration $config
```

### Project structure

```
MET/
├── MET.psd1                    # Module manifest
├── MET.psm1                    # Module root — dot-sources Public/ and Private/
├── Public/                     # Exported functions
├── Private/                     # Internal helpers
├── Checks/                      # Check scripts (MDO/ EXO/ Teams/)
├── Tests/Unit/                  # Pester 5 unit tests (no live tenant needed)
├── Tests/Integration/           # Integration tests (require live connection)
├── docs/checks/                 # One .md per check
├── docs/schema/                 # JSON Schema for report output
├── ROADMAP.md                   # Feature roadmap and known issues
└── .github/workflows/           # CI (Pester) + publish (PSGallery)
```

See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) for how to add a new check.

---

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the full feature roadmap and known issues.

---

## Contributing

See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).
