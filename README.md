<p align="center">
  <img src="assets/met-icon-light.svg#gh-light-mode-only" width="72" height="72" alt="MET logo">
  <img src="assets/met-icon-dark.svg#gh-dark-mode-only" width="72" height="72" alt="MET logo">
</p>

<h1 align="center">MET - Security Posture Scanner for MDO, EXO and Teams</h1>

<p align="center">Open-source PowerShell module for assessing the security posture of a Microsoft 365 tenant across Microsoft Defender for Office 365 (MDO), Exchange Online Protection (EOP), and Microsoft Teams threat protection.</p>

---

## Dependencies

### PowerShell

| Requirement | Detail |
|---|---|
| **Minimum** | PowerShell **7.4** |
| **Tested on** | PowerShell **7.4**, **7.6** |
| **Platform** | Windows (full support). Linux/macOS: all checks except DMARC (EXO001) and SPF (EXO003), which require `Resolve-DnsName` - a Windows-only cmdlet. `Connect-METSession` applies `-DisableWAM` automatically off-Windows, which is sufficient on a normal Linux/macOS desktop or a Codespace with a reachable browser tab - see [Teams sign-in on Linux/macOS](#teams-sign-in-on-linuxmacos). Device-code auth (`-UseDeviceAuthentication`) is only needed on a genuinely headless host with no browser reachable at all, and is a documented phishing vector otherwise - see the troubleshooting section below before using it. |

### Required modules

Exchange Online is the only hard requirement - every MDO and EXO check runs through it, and `Connect-METSession` aborts if it cannot connect.

```powershell
Install-Module ExchangeOnlineManagement -MinimumVersion 3.0.0 -Scope CurrentUser
```

### Optional modules

**Microsoft Graph** - used only by `Expand-METGroupMembership` to resolve group references. A missing module or a failed Graph connection is non-fatal: `Connect-METSession` warns and continues, and group expansion falls back to the Exchange Online cmdlets (`Get-DistributionGroupMember` for distribution and mail-enabled security groups, `Get-UnifiedGroupLinks` for Microsoft 365 Groups). Installing it is still recommended - Graph resolves nested and Azure AD security group membership more accurately.

```powershell
Install-Module Microsoft.Graph.Identity.SignIns -MinimumVersion 2.0.0 -Scope CurrentUser
Install-Module Microsoft.Graph.Groups           -MinimumVersion 2.0.0 -Scope CurrentUser
```

**MicrosoftTeams** - required by the Teams checks that call the native `Get-Cs*` cmdlets (Teams003, Teams005, Teams006, Teams007, Teams008). Teams001, Teams002, and Teams004 use Exchange-hosted cmdlets and run without it. If it is not installed, `Connect-METSession` logs a warning and the affected checks fail gracefully with an explanatory error in the result object.

```powershell
Install-Module MicrosoftTeams -MinimumVersion 6.0.0 -Scope CurrentUser
```

### Required M365 permissions

MET is **read-only** - it never modifies tenant configuration. Follow the principle of least privilege: grant only what is listed here.

#### Exchange Online

| Role / permission | Why it is needed |
|---|---|
| **Security Reader** (EXO role group) | Read all MDO/EOP policy cmdlets: `Get-SafeLinksPolicy`, `Get-AntiPhishPolicy`, `Get-MalwareFilterPolicy`, `Get-HostedContentFilterPolicy`, `Get-QuarantinePolicy`, `Get-TenantAllowBlockListItems`, `Get-ReportSubmissionPolicy`, `Get-DkimSigningConfig`, `Get-TransportRule`, `Get-AtpPolicyForO365`, `Get-ProtectionAlert`, `Get-Tag` |
| **View-Only Recipients** (EXO management role) | Enumerate mailboxes and distribution group membership (`Get-EXOMailbox`, `Get-DistributionGroupMember`, `Get-User`, `Get-AcceptedDomain`, `Get-EOPProtectionPolicyRule`) |

> The **Security Reader** EXO role group already includes View-Only Configuration, so you only need to add **View-Only Recipients** on top of it. Do _not_ use Organization Management or Security Administrator - those grant write access.

#### Microsoft Graph (Application permissions)

These are requested by `Connect-METSession`. All are **read-only**.

| Permission | Why it is needed |
|---|---|
| `Organization.Read.All` | Read tenant name and domain list |
| `Group.Read.All` | Resolve group membership for preset policy coverage (MDO008) |
| `Policy.Read.All` | Read the cross-tenant access default policy and authorization policy (MET-Teams014) |

> If you are running only Exchange/Teams checks and want to skip Graph entirely, use `Connect-METSession -SkipGraph`.

#### Microsoft Teams

| Role | Why it is needed |
|---|---|
| **Global Reader** (Microsoft Entra role) | Read Teams federation and meeting policy settings via `Get-CsTenantFederationConfiguration` and `Get-CsTeamsMeetingPolicy` |

> **Do not use Teams Administrator** - that role grants write access to Teams configuration. Global Reader is sufficient for all current Teams checks. If you do not run Teams checks, use `Connect-METSession -SkipTeams`.

#### App registration prerequisite: Exchange.ManageAsApp

Before any role assignment below can take effect, the app registration itself needs the **Office 365 Exchange Online → Exchange.ManageAsApp** **Application** permission, with **admin consent granted**. This is a separate mechanism from every role/permission in this section - Exchange Online rejects the connection with a bare `UnAuthorized` (no further detail) if it's missing, regardless of any RBAC role the service principal holds.

Portal: **App registrations** → your app → **API permissions** → **Add a permission** → **APIs my organization uses** → `Office 365 Exchange Online` → **Application permissions** → **Exchange** → `Exchange.ManageAsApp` → **Add permissions**, then **Grant admin consent for `<org>`**.

Or via `az` CLI:

```powershell
az ad app permission add --id $appId --api 00000002-0000-0ff1-ce00-000000000000 --api-permissions dc50a0fb-09a3-484d-be87-e023b12c6440=Role
az ad app permission admin-consent --id $appId
```

See Microsoft's [App-only authentication](https://learn.microsoft.com/powershell/exchange/app-only-auth-powershell-v2) doc for the full walkthrough, including certificate generation and attachment.

#### Assigning roles to a service principal (unattended / CI)

```powershell
# 1. Create the service principal in Exchange Online
New-ServicePrincipal -AppId $appId -ServiceId $spObjectId -DisplayName 'MET CI'

# 2. Grant the View-Only Recipients management role directly
New-ManagementRoleAssignment -Role 'View-Only Recipients' -App $appId

# 3. Grant Graph Application permissions in Entra (portal or CLI)
#    Organization.Read.All, Group.Read.All, Policy.Read.All

# 4. Assign Global Reader in Entra for Teams access
#    Microsoft Entra admin center → Roles → Global Reader → Add assignment → select the service principal
```

> **Security Reader is not assigned via `Add-RoleGroupMember`.** On many tenants `Get-RoleGroup -Identity 'Security Reader'` resolves to a role group that Microsoft's own docs describe as *"synchronized across services and managed centrally - you can't manage this role group in Exchange Online."* Assign it the same way as Global Reader above: **Microsoft Entra admin center → Roles → Security Reader → Add assignments → select the service principal** (or via Microsoft Graph `New-MgDirectoryRoleMemberByRef`). `Add-RoleGroupMember` against that role group fails with `'Security Reader' matches multiple entries` or is simply a no-op, not a working alternative.

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

> `-TenantId` must be the tenant's primary **`.onmicrosoft.com` domain name** (e.g. `contoso.onmicrosoft.com`), not the tenant GUID - `Connect-ExchangeOnline`'s `-Organization` parameter rejects GUIDs for app-only authentication. `Connect-METSession` fails fast with this same guidance if it detects a GUID. Graph and Teams accept either form, so the domain name works for all three legs.

`-CertificateThumbprint` reads from the Windows certificate store and is Windows-only. On Linux/macOS/Codespaces, use `-CertificatePath` + `-CertificatePassword` instead - this is also the recommended alternative to device-code auth for unattended/CI use on any non-Windows host:

```powershell
$certPassword = ConvertTo-SecureString $env:MET_CERT_PASSWORD -AsPlainText -Force
Connect-METSession `
    -AppId           $appId `
    -TenantId        $tenantId `
    -CertificatePath './met-ci.pfx' `
    -CertificatePassword $certPassword
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

# MSSP - run against a delegated tenant
Invoke-METTriage -DelegatedOrganization contoso.onmicrosoft.com
```

### Switching tenants (MSSP / delegated admin)

`Connect-METSession` reuses a live Exchange Online/Graph/Teams connection rather than reconnecting on every call - but it verifies the reused connection actually belongs to the tenant you just asked for, and throws (naming the actually-connected org) if it doesn't, rather than silently handing back a report for the wrong customer. Before switching to a different `-DelegatedOrganization`, run `Disconnect-METSession` first:

```powershell
Connect-METSession -DelegatedOrganization customerA.onmicrosoft.com
$resultsA = Invoke-METTriage

Disconnect-METSession
Connect-METSession -DelegatedOrganization customerB.onmicrosoft.com
$resultsB = Invoke-METTriage
```

### Skip a service

```powershell
# Skip Teams connection (if MicrosoftTeams module is not installed)
Connect-METSession -SkipTeams

# Skip Graph (if only running EXO checks that don't need Graph)
Connect-METSession -SkipGraph
```

### Exchange sign-in troubleshooting

Try these in order. Device-code auth is a documented phishing vector ([Storm-2372](https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/) and follow-on campaigns) - Microsoft's own guidance is "block wherever possible, allow only where necessary." `Connect-METSession` emits a `Write-Warning` whenever `-UseDeviceAuthentication` is actually used, and it should be your last resort, not the default retry.

```powershell
# 1. On Windows, or any host with a reachable browser: disable WAM first
Connect-METSession -SkipGraph -SkipTeams -DisableWAM -Verbose

# 2. Optional: pre-select the account instead of / alongside the above
Connect-METSession -UserPrincipalName admin@contoso.com -Verbose

# 3. Unattended/CI on a non-Windows host: use a certificate file, not device code
Connect-METSession -AppId $appId -TenantId $tenantId -CertificatePath './met-ci.pfx' -CertificatePassword $certPassword

# 4. Last resort - only on a genuinely headless host with no browser reachable at all
Connect-METSession -SkipGraph -SkipTeams -UseDeviceAuthentication -Verbose
```

**`Failed to connect to Exchange Online: UnAuthorized`** with service-principal/certificate auth means the certificate and tenant were accepted, but the app itself isn't authorized: it is almost always the app registration missing the `Exchange.ManageAsApp` API permission (with admin consent granted) described in [App registration prerequisite: Exchange.ManageAsApp](#app-registration-prerequisite-exchangemanageasapp) above - a distinct requirement from any Exchange RBAC role or Entra directory role. A role assignment alone (Security Reader, View-Only Recipients, etc.) never fixes this error on its own.

#### Known warning: Microsoft Graph MSAL version conflict

```
WARNING: Failed to connect to Microsoft Graph: ClientCertificateCredential authentication failed: Method not found:
'!0 Microsoft.Identity.Client.BaseAbstractApplicationBuilder`1.WithLogging(Microsoft.IdentityModel.Abstractions.IIdentityLogger, Boolean)'.
```

This is expected on some machines and is safe to ignore - it is not specific to certificate/CI auth, and every admin running `Connect-METSession` interactively can hit it too. `ExchangeOnlineManagement` and `Microsoft.Graph.*` each bundle their own version of `Microsoft.Identity.Client` (MSAL); whichever one loads into the PowerShell process first "wins" for the whole session, and the other module ends up calling a method signature that doesn't exist in that loaded version. This is release-cadence drift between Microsoft's own modules, not a MET bug or a misconfiguration, and there is no currently-published combination of module versions that reliably avoids it.

`Connect-METSession` already treats this as non-fatal by design: Exchange Online and Teams connect normally, and `Expand-METGroupMembership` falls back to `Get-DistributionGroupMember`/`Get-UnifiedGroupLinks` for group expansion instead of Graph. The only effect is slightly reduced accuracy resolving nested/dynamic group membership, and `MET-Teams014` reporting `NotApplicable` instead of running. If you need Graph checks to actually run, the only reliable workaround is connecting Graph in its own PowerShell process rather than alongside Exchange Online.

#### Teams sign-in on Linux/macOS

MicrosoftTeams **7.9.0** (July 2026) made Web Account Manager (WAM) the default authentication broker for `Connect-MicrosoftTeams`. WAM is Windows-only - it calls into `kernel32.dll` - so on Linux and macOS the default interactive sign-in fails before any network request:

```
Connect-MicrosoftTeams: Unable to load shared library 'kernel32.dll' or one of its dependencies.
```

`Connect-METSession` already applies `-DisableWAM` automatically off-Windows, which resolves this on its own - no extra flag needed on a normal Linux/macOS desktop or a Codespace with a reachable browser tab:

```powershell
Connect-METSession -Verbose
```

Device-code authentication (`-UseDeviceAuthentication`) is only the right answer on a genuinely **headless** host - no browser reachable at all (a bare CI runner, an SSH-only box). It is not "the Linux/macOS answer" generally; see the phishing-risk note above before reaching for it. MicrosoftTeams 6.0.0 through 7.8.0 are unaffected by the WAM change either way.

---

## Custom Policy Baseline - Promotions Folder

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

Users in `Promotions-OptIn` must be excluded from both the Standard and Strict preset scope, otherwise the preset wins the priority order and the custom policies never apply. Presets have two rule sets: EOP (anti-spam, anti-phish, anti-malware) and ATP (Safe Links, Safe Attachments).

```powershell
# View current preset scope
Get-EOPProtectionPolicyRule | Format-List Name, SentToMemberOf, ExceptIfSentToMemberOf
Get-ATPProtectionPolicyRule | Format-List Name, SentToMemberOf, ExceptIfSentToMemberOf

# Exclude from Strict preset - EOP rules
Set-EOPProtectionPolicyRule `
    -Identity               'Strict Preset Security Policy' `
    -ExceptIfSentToMemberOf 'Promotions-OptIn'

# Exclude from Strict preset - ATP rules (Safe Links + Safe Attachments)
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

---

## Check Inventory

### MDO - Microsoft Defender for Office 365

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
| MET-MDO013 | Policy Precedence Conflicts | High | Custom rules targeting recipients already covered by a Standard/Strict preset |
| MET-MDO014 | Group Reference Audit | High | Groups referenced by policy rules (SentToMemberOf) that are empty or cannot be resolved |

### EXO - Exchange Online / Email Authentication

| ID | Name | Severity | What it assesses |
|---|---|---|---|
| MET-EXO001 | DMARC | High | Record present, policy quarantine/reject, rua reporting |
| MET-EXO002 | DKIM | High | Signing enabled, key ≥ 2048 bit, CNAME status valid |
| MET-EXO003 | SPF | High | Record present, -all enforcement, ≤ 10 DNS lookups |
| MET-EXO004 | Quarantine Policies | Medium | Custom (non-built-in) quarantine policies with notifications off but end-user permissions granted |
| MET-EXO005 | Tenant Allow/Block List | Low | Stale allows (>90 days), wildcard allows, allow/block ratio |
| MET-EXO006 | Submission Policy | Medium | Report-to-Microsoft on, custom submission mailbox configured |
| MET-EXO007 | Transport Rule Audit | Medium | Rules bypassing spam filter (SCL=-1) or disabling Safe Links |
| MET-EXO008 | Quarantine Retention | Medium | QuarantineRetentionPeriod ≥ 30 days in default/custom anti-spam policies (presets reported as fixed, not actionable) |
| MET-EXO009 | Quarantine Policy Verdict Alignment | Medium | Quarantine tags not too permissive for Malware/High-Confidence Phish (the only verdicts Microsoft itself restricts); preset policies skipped |
| MET-EXO010 | Direct Send | Critical | RejectDirectSend enabled so unauthenticated senders cannot relay as an internal domain |
| MET-EXO011 | Mail Flow Connector Hygiene | High | Inbound connectors with RequireTls off or no source IP / certificate authentication binding |
| MET-EXO012 | Mailbox Forwarding | Critical | Mailboxes with SMTP forwarding configured, flagging silent (no local copy) forwarding |
| MET-EXO013 | Spoof Intelligence Allow-List | High | Standing spoof-intelligence allow entries, split by Internal vs External spoof type |
| MET-EXO014 | Advanced Delivery Policy | Medium | Phishing-simulation and SecOps mailbox override rules listed for periodic review |
| MET-EXO015 | External Sender Warning Tag | Medium | Native Outlook "External" sender banner enabled (Get-ExternalInOutlook) |
| MET-EXO016 | ARC Trusted Sealers | Low | Domains trusted to vouch for authentication results via Authenticated Received Chain |
| MET-EXO017 | Quarantine Notification Cadence | Informational | EndUserSpamNotificationFrequency on the global quarantine policy (4 hours / 1 day / 7 days) |
| MET-EXO018 | Remote Domain Automatic Forwarding | High | AutoForwardEnabled per remote domain - the tenant-wide `*` domain permitting auto-forward to every external domain is the BEC exfiltration path |
| MET-EXO019 | SMTP Client Authentication | High | Tenant-wide SmtpClientAuthenticationDisabled plus per-mailbox overrides that re-enable legacy SMTP AUTH |
| MET-EXO020 | Connection Filter Policy Hygiene | High | IPAllowList entries (which skip spam filtering and spoof intelligence) and EnableSafeList |
| MET-EXO021 | Mailbox Audit Logging | Medium | Organization-wide AuditDisabled - the evidence base a BEC investigation depends on |
| MET-EXO022 | Calendar and Contact Sharing | Medium | Sharing policies exposing calendar detail or contacts to all domains or anonymously |
| MET-EXO023 | Unified Audit Log Ingestion | High | UnifiedAuditLogIngestionEnabled (retention duration is a documented manual review item, not asserted here) |

### Teams - Microsoft Teams Threat Protection

| ID | Name | Severity | What it assesses |
|---|---|---|---|
| MET-Teams001 | Safe Links for Teams | High | Effective, precedence-resolved Safe Links policy per mailbox (same preset-vs-custom resolver as MET-MDO001) has EnableSafeLinksForTeams enabled |
| MET-Teams002 | Safe Attachments for Teams | High | EnableATPForSPOTeamsODB (the single documented toggle for SPO/OneDrive/Teams) |
| MET-Teams003 | Meeting Protection | Medium | Anonymous join, lobby bypass (AutoAdmittedUsers, AllowPSTNUsersToBypassLobby), federation - across all meeting policies |
| MET-Teams004 | ZAP for Teams | High | TeamsProtectionPolicy ZAP enabled; malware and high-confidence phish quarantine tags set to AdminOnlyAccessPolicy; rule-level exceptions that narrow coverage |
| MET-Teams005 | Teams User Reporting | Low | ReportChatMessageEnabled in report submission policy; AllowSecurityEndUserReporting in Teams messaging policy |
| MET-Teams006 | External Access / Federation | High | Open federation (AllowAllKnownDomains), AllowTeamsConsumer/AllowTeamsConsumerInbound, and an empty BlockedDomains deny-list |
| MET-Teams007 | Guest Messaging/Calling | Medium | Guest-initiated 1:1 chat and private calling configuration |
| MET-Teams008 | App Permission Policy Exposure | Medium | Catalog app types not restricted to an explicit allow/block list (may be inert on ACM-migrated tenants) |
| MET-Teams009 | Trial Tenant Federation Exposure | High | ExternalAccessWithTrialTenants allows communication with disposable trial-license tenants |
| MET-Teams010 | External Access Policy Drift | Medium | Non-Global CsExternalAccessPolicy instances re-opening federation/public-cloud access for a specific user set |
| MET-Teams011 | SecOps Blocklist Authority | Medium | Whether SecOps can block malicious domains/users from the Defender portal mid-incident, plus what's currently blocked |
| MET-Teams012 | Call Reporting | Medium | ReportCall in Teams calling policies - the native control against helpdesk-vishing calls |
| MET-Teams014 | Cross-Tenant Guest Access | Medium | Entra cross-tenant access default policy and guest-invite authorization (Graph, degrades gracefully if unavailable) |
| MET-Teams015 | Teams Email Integration | Medium | AllowEmailIntoChannel - channel email addresses accept external mail that never traverses the mailbox delivery path |

---

## Manual Review Items

Settings MET deliberately does not assess as a check. Two different reasons land a setting here:

- **Genuinely unautomatable** - no supported PowerShell cmdlet or public Microsoft Graph API exists to read or set the setting at all. A check with no data source would emit identical, static output on every run regardless of actual tenant state, which doesn't fit MET's assessment model.
- **Automatable, but deliberately excluded** - a real cmdlet exists, but only via a PowerShell module (and, usually, a separate authenticated connection) MET doesn't otherwise need. MET's dependency footprint is intentionally kept to `ExchangeOnlineManagement` (required) plus `MicrosoftTeams` and `Microsoft.Graph.*` (both optional, both already justified by checks that need them) - see [Dependencies](#dependencies). Adding a module for one setting isn't worth the extra auth prompt, permission grant, and install step every user would carry for it.

### AIR (Automated investigation and response) auto-remediation

*Genuinely unautomatable.* [Automated remediation in AIR](https://learn.microsoft.com/en-us/defender-office-365/air-auto-remediation) documents portal-only configuration; the Microsoft Graph Security API (`security/alerts`, `security/incidents`, beta `securityAction`) has no `automatedInvestigation`/`airConfiguration` resource in v1.0 or beta. The Defender portal UI is backed by an internal endpoint (`/apiproxy/di/Find/AirConfiguration?tenantid=<tenantId>`) with no supported public surface to call.

**Review manually:** Defender portal → Settings → Email & collaboration → MDO automation settings (`https://security.microsoft.com/securitysettings/mdoAutomationSettings`).

**What it configures:** an opt-in toggle per message-cluster type - *Similar files*, *Similar URLs*, *Multiple similar attributes* - all mapped to a single action, **Soft delete** (to Recoverable Items). Clusters over 10,000 messages always require manual approval in the Action Center regardless of this setting.

**Baseline:** Microsoft has not published this as part of the Standard/Strict preset security policies, so there's no single mandated value. Enabling it speeds remediation for these three well-understood, high-confidence cluster types, at the cost of the mailbox's normal deleted-item retention window being the only recovery path - treat it as an org-specific speed-vs-recoverability trade-off during review, not a compliance gap.

### Blocking downloads of infected files (SharePoint/OneDrive/Teams)

*Automatable, but deliberately excluded.* `Get-SPOTenant | Format-List DisallowInfectedFileDownload` is the only way to read this setting - it isn't part of Microsoft Graph's `sharepointSettings` resource (verified against the full property list: sharing, site-creation, and storage settings only, nothing malware-related). Reading it would require adding `Microsoft.Online.SharePoint.PowerShell` (or PnP.PowerShell), a new `Connect-SPOService` authentication flow, and the tenant's SPO admin URL - a new dependency family for one boolean, so MET doesn't add it.

**Review manually:** connect via [SharePoint Online PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.online.sharepoint.powershell/connect-sposervice) and run `Get-SPOTenant | Format-List DisallowInfectedFileDownload`.

**What it configures:** by default, users can delete and download malware-detected files in SharePoint/OneDrive/Teams (they can't open, move, copy, or share them - except via **Manage access**, where **Share** still works). Setting `Set-SPOTenant -DisallowInfectedFileDownload $true` additionally blocks the download path, for both users and admins. People can still delete a malicious file either way.

**Related MET check:** [MET-Teams002](docs/checks/MET-Teams002-SafeAttachments.md) verifies the prerequisite (`EnableATPForSPOTeamsODB`) that makes malware detection happen in the first place - this setting only matters once that's on.

### Alert policy for malware detected in SharePoint/OneDrive/Teams

*Automatable, but deliberately excluded.* `Get-ProtectionAlert`/`New-ProtectionAlert` ship in `ExchangeOnlineManagement` (no new module), but only work over [Security & Compliance PowerShell](https://learn.microsoft.com/en-us/powershell/exchange/connect-to-scc-powershell) (`Connect-IPPSSession`) - a second authenticated session distinct from `Connect-ExchangeOnline`, requiring Purview compliance-portal permissions (e.g. Compliance Administrator) beyond the Security Reader role every other MET check is documented to work with. A second session per run, for one Info-level listing check, wasn't judged worth the added auth prompt and permission ask.

**Review manually:** Defender portal → Email & collaboration → Alert policy (`https://security.microsoft.com/alertpolicies`) → confirm a policy exists for **Detected malware in file**, with admin notification recipients configured.

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

The HTML report is a **single self-contained file** - all CSS and JavaScript are inlined, no CDN or internet connection required to view it.

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

The unit suite includes `Tests/Unit/Get-METReport.Html.Tests.ps1`, which asserts the
generated HTML report is self-contained (no external script, stylesheet or CDN reference),
escapes hostile text in both the rendered markup and the embedded JSON, never emits a live
`href` for a `javascript:`/`data:` reference URL, and renders correctly for empty and
single-result runs. No browser is needed for those.

The interactive behaviour of the report - tab switching, live search, the severity/result
filters, card expansion, and the accept-risk flow with its `localStorage` persistence - is
covered by a separate browser-driven suite that is not part of the PowerShell run:

```bash
cd Tests/Html
npm ci
npx playwright test
```

It regenerates its fixtures by invoking `Get-METReport` from the working tree on every run,
so it always tests the current generator rather than a checked-in HTML file. See
`Tests/Html/README.md` for browser resolution and CI notes.

### Project structure

```
MET/
├── MET.psd1                    # Module manifest
├── MET.psm1                    # Module root - dot-sources Public/ and Private/
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

MIT - see [LICENSE](LICENSE).
