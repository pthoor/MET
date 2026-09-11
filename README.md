<p align="center">
  <img src="assets/met-icon-light.svg#gh-light-mode-only" width="72" height="72" alt="MET logo">
  <img src="assets/met-icon-dark.svg#gh-dark-mode-only" width="72" height="72" alt="MET logo">
</p>

<h1 align="center">MET - Security Posture Scanner for MDO, EXO and Teams</h1>

[![CI](https://github.com/pthoor/MET/actions/workflows/pester.yml/badge.svg)](https://github.com/pthoor/MET/actions/workflows/pester.yml)
[![Latest release](https://img.shields.io/github/v/release/pthoor/MET)](https://github.com/pthoor/MET/releases/latest)

<p align="center">Open-source PowerShell module for assessing the security posture of a Microsoft 365 tenant across Microsoft Defender for Office 365 (MDO), Exchange Online Protection (EOP), and Microsoft Teams threat protection.</p>

MET runs 51 read-only security posture checks across Microsoft Defender for Office 365, Exchange Online Protection, and Microsoft Teams.

## Quick start

```powershell
Install-Module MET -Repository PSGallery -Scope CurrentUser
Test-METPrerequisites
Connect-METSession
$results = Invoke-METAssessment
$results | Get-METReport -Format HTML -OutputPath ./assessments
```

---

## Dependencies

### PowerShell

| Requirement | Detail |
|---|---|
| **Minimum** | PowerShell **7.4** |
| **Tested on** | PowerShell **7.4**, **7.6** |
| **Platform** | All 51 checks run on Windows, Linux, and macOS. EXO001 and EXO003 use `Resolve-DnsName` on Windows, then `dig`, `nslookup`, and configurable DNS-over-HTTPS elsewhere. DNS-over-HTTPS discloses queried domains to its resolver and can be disabled with `MET_DOH_RESOLVER=none`. `Connect-METSession` applies `-DisableWAM` automatically off-Windows, which is sufficient on a normal Linux/macOS desktop or a Codespace with a reachable browser tab - see [Teams sign-in on Linux/macOS](#teams-sign-in-on-linuxmacos). Device-code auth (`-UseDeviceAuthentication`) is only needed on a genuinely headless host with no browser reachable at all, and is a documented phishing vector otherwise - see the troubleshooting section below before using it. |

### Required modules

Exchange Online is the only hard requirement - every MDO and EXO check runs through it, and `Connect-METSession` aborts if it cannot connect.

```powershell
Install-Module ExchangeOnlineManagement -MinimumVersion 3.7.2 -Scope CurrentUser
```

The floor is `-DisableWAM`, the switch `Connect-METSession` passes automatically off Windows; derived in `docs/superpowers/notes/2026-09-10-exo-version-floor.md`. Note EXO's own supported-OS table requires PowerShell 7.6.0+ starting at module 3.10.0 (3.5.0-3.9.2 need only 7.4.0+) - on MET's PowerShell 7.4 floor, EXO 3.10.x cannot be installed at all.

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
| **Security Reader** (EXO role group) | Read all MDO/EOP policy cmdlets: `Get-SafeLinksPolicy`, `Get-AntiPhishPolicy`, `Get-MalwareFilterPolicy`, `Get-HostedContentFilterPolicy`, `Get-QuarantinePolicy`, `Get-TenantAllowBlockListItems`, `Get-ReportSubmissionPolicy`, `Get-DkimSigningConfig`, `Get-TransportRule`, `Get-AtpPolicyForO365` |
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

## Usage

`Invoke-METTriage` remains available as an alias for `Invoke-METAssessment`.

| Option | Current behavior |
|---|---|
| `Connect-METSession -ManagedIdentity` | Authenticates from an Azure host using its system-assigned managed identity by default, or the identity named by `-ManagedIdentityAccountId`. |
| `Connect-METSession -SkipExchangeOnline` | Skips Exchange Online; all MDO and EXO checks plus Teams001, Teams002, and Teams004 need it and fail without it. |
| `Invoke-METAssessment -ListChecks` | Lists the checks selected by the scope parameters without connecting or running checks. |
| `Invoke-METAssessment -Detailed` | Returns full, unaggregated per-object results instead of the default one-summary-result-per-check view. |
| `Get-METReport -PassThru` | Returns a `System.IO.FileInfo` for each report file actually written to disk. |

### Discover checks before connecting

```powershell
# List every check MET can run - no module, connection, or tenant required
Get-METCheck

# Scope to a category or severity
Get-METCheck -Category EXO
Get-METCheck -Severity Critical, High

# Look up specific checks by ID
Get-METCheck -CheckId MET-EXO001, MET-MDO009
```

`Get-METCheck` reads each check's declared name, severity, description, and required module straight off the script file, so it works before you have run `Connect-METSession` at all - useful for deciding what a check does, or which `-Category`/`-CheckId`/`-Severity` scope you want, before connecting to a tenant. `Invoke-METAssessment -ListChecks` uses the same data.

### Service Principal (unattended / CI)

```powershell
Connect-METSession `
    -AppId               $appId `
    -TenantId            $tenantId `
    -CertificateThumbprint $thumb

$results = Invoke-METAssessment
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
Invoke-METAssessment -Category MDO

# EXO checks only
Invoke-METAssessment -Category EXO

# Teams checks only (requires MicrosoftTeams module)
Invoke-METAssessment -Category Teams

# Specific check IDs
Invoke-METAssessment -CheckId MET-MDO001, MET-EXO001

# All checks except transport rule audit (informational)
Invoke-METAssessment -ExcludeCheckId MET-EXO007
```

### Multi-tenant / MSSP access

If you assess more than one customer tenant, decide how you get in first, then follow one rule: **one tenant per PowerShell process**.

| Access model | When it fits | How you connect |
|---|---|---|
| **GDAP / delegated admin (CSP)** | You have a GDAP relationship with each customer from your partner tenant | Your own partner account, once, with `-DelegatedOrganization <customer>.onmicrosoft.com` per customer |
| **App-only + certificate** (best for repeatable engagements) | You can get an app registration consented in each customer tenant | Per-customer `-AppId -TenantId <customer>.onmicrosoft.com -CertificatePath -CertificatePassword` - no interactive prompt |
| **Guest / dedicated account per tenant** | The customer issued you an account with Security Reader plus the Exchange/Teams read roles | Interactive sign-in with that customer-specific account |

For app-only auth **that includes Exchange Online**, `-TenantId` **must be the customer's `.onmicrosoft.com` domain, not the tenant GUID** - `Connect-ExchangeOnline`'s app-only `-Organization` rejects GUIDs, and `Connect-METSession` fails fast if you pass one. A GUID is accepted with `-SkipExchangeOnline` (Graph and Teams take either form).

**One tenant per process.** `Connect-METSession` reuses a live Exchange Online/Graph/Teams connection rather than reconnecting on every call, but it verifies the reused connection belongs to the tenant you just asked for and throws (naming the actually-connected org) if it doesn't - so a forgotten disconnect can't silently hand you customer A's data in a report labelled customer B. It also refuses outright if Exchange Online has live sessions for more than one org. Beyond MET, the Exchange Online, Graph, and Teams modules share one MSAL assembly context per process, so tenant residue is a real risk. Between customers, either run `Disconnect-METSession` and reconnect, or - cleaner - use a fresh PowerShell window per customer.

```powershell
Connect-METSession -DelegatedOrganization customerA.onmicrosoft.com
Invoke-METAssessment | Get-METReport -Format All -OutputPath ./assessments/customerA-2026-09-09/

Disconnect-METSession
Connect-METSession -DelegatedOrganization customerB.onmicrosoft.com
Invoke-METAssessment | Get-METReport -Format All -OutputPath ./assessments/customerB-2026-09-09/
```

Give each customer its own `-OutputPath`. The report header (console/JSON/HTML) records the auth mode, tenant, and services used for the run, from state `Connect-METSession` sets on success - send that to the customer's SOC so they can reconcile your sign-in against a known MET run instead of triaging it as an incident.

> `Invoke-METAssessment -DelegatedOrganization` is a placeholder and does not scope anything yet - the delegation happens entirely at `Connect-METSession` time, and `Invoke-METAssessment` then runs against whatever session is live. Under GDAP, Graph checks degrade non-fatally: group expansion falls back to Exchange Online cmdlets and `MET-Teams014` reports `NotApplicable` unless the delegated Graph roles are present.

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

**`Error Acquiring Token ... 0x80070520 'A specified logon session does not exist'`** on Windows is a WAM (Web Account Manager) broker error, not a MET fault. WAM needs an interactive desktop logon session to attach to; it fails with this code when the console has none - most often an **elevated ("Run as administrator") prompt** (the elevated token is a different logon session from your signed-in desktop), or a remote/service/scheduled-task session. None of the MET cmdlets need local admin. Retry from a **normal, non-elevated** PowerShell 7 window, or bypass the broker with `-DisableWAM` (step 1 above). For unattended or non-interactive hosts, use certificate auth (step 3).

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

## Optional remediation baseline

MET is assessment-only and never changes tenant configuration. The separate [Promotions Folder baseline](docs/baselines/promotions-folder.md) is optional deployment guidance for administrators who deliberately want that mail-flow design; its `New-*` and `Set-*` commands are not run by MET.

## Check Inventory

### MDO - Microsoft Defender for Office 365

| ID | Name | Severity | What it assesses |
|---|---|---|---|
| [MET-MDO001](docs/checks/MET-MDO001-SafeLinks.md) | Safe Links Effective Coverage | High | Email + Office app URL scanning, click-through, internal senders |
| [MET-MDO002](docs/checks/MET-MDO002-SafeAttachments.md) | Safe Attachments | High | Policy enabled, action is Block or DynamicDelivery |
| [MET-MDO003](docs/checks/MET-MDO003-AntiPhish.md) | Anti-Phishing Effective Coverage | High | Mailbox intelligence, impersonation protection, safety tips |
| [MET-MDO004](docs/checks/MET-MDO004-AntiSpoofing.md) | Anti-Spoofing | High | Spoof intelligence, DMARC honor, auth failure action |
| [MET-MDO005](docs/checks/MET-MDO005-AntiMalware.md) | Anti-Malware Effective Coverage | High | ZAP, common attachment filter, admin notifications |
| [MET-MDO006](docs/checks/MET-MDO006-AntiSpamInbound.md) | Anti-Spam Inbound Effective Coverage | Medium | Spam/phish actions, high-confidence thresholds, BCL |
| [MET-MDO007](docs/checks/MET-MDO007-AntiSpamOutbound.md) | Anti-Spam Outbound Effective Coverage | High | Auto-forward disabled, send limit action, admin alerts |
| [MET-MDO008](docs/checks/MET-MDO008-PresetPolicyCoverage.md) | Preset Policy Coverage | High | % of mailboxes covered by Standard or Strict preset |
| [MET-MDO009](docs/checks/MET-MDO009-ZAP.md) | ZAP Effective Coverage | High | ZAP enabled for spam and phishing in all policies |
| [MET-MDO010](docs/checks/MET-MDO010-PriorityAccounts.md) | Priority Account Protection Toggle | High | Priority Account tag usage + differentiated protection policy |
| [MET-MDO011](docs/checks/MET-MDO011-UserTags.md) | User Tags | Low | Portal-review pointer for user tags and tag-aware alert policies; no programmatic assessment (always Info/Low). |
| [MET-MDO012](docs/checks/MET-MDO012-SafeDocuments.md) | Safe Documents | Medium | EnableSafeDocs enabled; AllowSafeDocsOpen disabled |
| [MET-MDO013](docs/checks/MET-MDO013-PolicyPrecedenceConflicts.md) | Policy Precedence Conflicts | High | Custom rules targeting recipients already covered by a Standard/Strict preset |
| [MET-MDO014](docs/checks/MET-MDO014-GroupReferenceAudit.md) | Group Reference Audit | High | Groups referenced by policy rules (SentToMemberOf) that are empty or cannot be resolved |

### EXO - Exchange Online / Email Authentication

| ID | Name | Severity | What it assesses |
|---|---|---|---|
| [MET-EXO001](docs/checks/MET-EXO001-DMARC.md) | DMARC | High | Record present, policy quarantine/reject, rua reporting |
| [MET-EXO002](docs/checks/MET-EXO002-DKIM.md) | DKIM | High | Signing enabled, key ≥ 2048 bit, CNAME status valid |
| [MET-EXO003](docs/checks/MET-EXO003-SPF.md) | SPF | High | Record present, -all enforcement, ≤ 10 DNS lookups |
| [MET-EXO004](docs/checks/MET-EXO004-QuarantinePolicy.md) | Quarantine Policies | Medium | Custom (non-built-in) quarantine policies with notifications off but end-user permissions granted |
| [MET-EXO005](docs/checks/MET-EXO005-TenantAllowBlockList.md) | Tenant Allow/Block List | Low | Stale allows (>90 days), wildcard allows, allow/block ratio |
| [MET-EXO006](docs/checks/MET-EXO006-SubmissionPolicy.md) | User Reported Message Settings | High | Report-to-Microsoft on, custom submission mailbox configured |
| [MET-EXO007](docs/checks/MET-EXO007-TransportRuleAudit.md) | Transport Rule Audit | Medium | Rules bypassing spam filter (SCL=-1) or disabling Safe Links |
| [MET-EXO008](docs/checks/MET-EXO008-QuarantineRetention.md) | Quarantine Retention | Low | QuarantineRetentionPeriod ≥ 30 days in default/custom anti-spam policies (presets reported as fixed, not actionable) |
| [MET-EXO009](docs/checks/MET-EXO009-QuarantinePolicyVerdictAlignment.md) | Quarantine Policy Verdict Alignment | High | Quarantine tags not too permissive for Malware/High-Confidence Phish (the only verdicts Microsoft itself restricts); preset policies skipped |
| [MET-EXO010](docs/checks/MET-EXO010-DirectSend.md) | Direct Send Protection | Critical | RejectDirectSend enabled so unauthenticated senders cannot relay as an internal domain |
| [MET-EXO011](docs/checks/MET-EXO011-ConnectorHygiene.md) | Mail Flow Connector Hygiene | High | Inbound connectors with RequireTls off or no source IP / certificate authentication binding |
| [MET-EXO012](docs/checks/MET-EXO012-MailboxForwarding.md) | Mailbox Forwarding | High | Mailboxes with SMTP forwarding configured - Pass when none forward, Info when every forward retains a local copy, Warning on silent (no local copy) forwarding or an unreturned `DeliverToMailboxAndForward` |
| [MET-EXO013](docs/checks/MET-EXO013-SpoofIntelligenceAllowList.md) | Spoof Intelligence Allow-List | High | Standing spoof-intelligence allow entries, split by Internal vs External spoof type |
| [MET-EXO014](docs/checks/MET-EXO014-AdvancedDeliveryPolicy.md) | Advanced Delivery Policy | Medium | Phishing-simulation and SecOps mailbox override rules listed for periodic review |
| [MET-EXO015](docs/checks/MET-EXO015-ExternalSenderTag.md) | External Sender Warning Tag | Medium | Native Outlook "External" sender banner enabled (Get-ExternalInOutlook) |
| [MET-EXO016](docs/checks/MET-EXO016-ArcTrustedSealers.md) | ARC Trusted Sealers Review | Low | Domains trusted to vouch for authentication results via Authenticated Received Chain |
| [MET-EXO017](docs/checks/MET-EXO017-QuarantineNotificationCadence.md) | Quarantine Notification Cadence | Low | EndUserSpamNotificationFrequency on the global quarantine policy (4 hours / 1 day / 7 days) |
| [MET-EXO018](docs/checks/MET-EXO018-RemoteDomainForwarding.md) | Remote Domain Automatic Forwarding | High | AutoForwardEnabled per remote domain - the tenant-wide `*` domain permitting auto-forward to every external domain is the BEC exfiltration path |
| [MET-EXO019](docs/checks/MET-EXO019-SmtpAuthentication.md) | SMTP Client Authentication | High | Tenant-wide SmtpClientAuthenticationDisabled plus per-mailbox overrides that re-enable SMTP AUTH |
| [MET-EXO020](docs/checks/MET-EXO020-ConnectionFilterPolicy.md) | Connection Filter Policy Hygiene | High | IPAllowList entries (which skip spam filtering and spoof intelligence) and EnableSafeList |
| [MET-EXO021](docs/checks/MET-EXO021-MailboxAuditing.md) | Mailbox Audit Logging | Medium | Organization-wide AuditDisabled - the evidence base a BEC investigation depends on |
| [MET-EXO022](docs/checks/MET-EXO022-SharingPolicy.md) | Calendar and Contact Sharing Policies | Medium | Sharing policies exposing calendar detail or contacts to all domains or anonymously |
| [MET-EXO023](docs/checks/MET-EXO023-UnifiedAuditLog.md) | Unified Audit Log Ingestion | High | UnifiedAuditLogIngestionEnabled (retention duration is a documented manual review item, not asserted here) |

### Teams - Microsoft Teams Threat Protection

| ID | Name | Severity | What it assesses |
|---|---|---|---|
| [MET-Teams001](docs/checks/MET-Teams001-SafeLinks.md) | Safe Links for Teams | High | Effective, precedence-resolved Safe Links policy per mailbox (same preset-vs-custom resolver as MET-MDO001) has EnableSafeLinksForTeams enabled |
| [MET-Teams002](docs/checks/MET-Teams002-SafeAttachments.md) | Safe Attachments for Teams | High | EnableATPForSPOTeamsODB (the single documented toggle for SPO/OneDrive/Teams) |
| [MET-Teams003](docs/checks/MET-Teams003-MeetingProtection.md) | Meeting Protection | Medium | Anonymous join, lobby bypass (AutoAdmittedUsers, AllowPSTNUsersToBypassLobby), federation - across all meeting policies |
| [MET-Teams004](docs/checks/MET-Teams004-ZAPForTeams.md) | ZAP for Teams | High | TeamsProtectionPolicy ZAP enabled; malware and high-confidence phish quarantine tags set to AdminOnlyAccessPolicy; rule-level exceptions that narrow coverage |
| [MET-Teams005](docs/checks/MET-Teams005-TeamsUserReporting.md) | Teams User Reporting | Medium | ReportChatMessageEnabled in report submission policy; AllowSecurityEndUserReporting in Teams messaging policy |
| [MET-Teams006](docs/checks/MET-Teams006-ExternalAccess.md) | External Access / Federation Allow-List | High | Open federation (AllowAllKnownDomains), AllowTeamsConsumer/AllowTeamsConsumerInbound, and an empty BlockedDomains deny-list |
| [MET-Teams007](docs/checks/MET-Teams007-GuestConfiguration.md) | Guest Messaging/Calling Configuration | Medium | Guest-initiated 1:1 chat and private calling configuration |
| [MET-Teams008](docs/checks/MET-Teams008-AppPermissionPolicy.md) | App Permission Policy | Medium | Catalog app types not restricted to an explicit allow/block list (may be inert on ACM-migrated tenants) |
| [MET-Teams009](docs/checks/MET-Teams009-TrialTenantFederation.md) | Trial Tenant Federation Exposure | High | ExternalAccessWithTrialTenants allows communication with disposable trial-license tenants |
| [MET-Teams010](docs/checks/MET-Teams010-ExternalAccessPolicyDrift.md) | Per-User External Access Policy Drift | Medium | Non-Global CsExternalAccessPolicy instances re-opening federation/public-cloud access for a specific user set |
| [MET-Teams011](docs/checks/MET-Teams011-SecOpsBlocklistAuthority.md) | SecOps Blocklist Authority & Blocked Entities | Medium | Whether SecOps can block malicious domains/users from the Defender portal mid-incident, plus what's currently blocked |
| [MET-Teams012](docs/checks/MET-Teams012-CallReporting.md) | Call Reporting | Medium | ReportCall in Teams calling policies - the native control against helpdesk-vishing calls |
| [MET-Teams014](docs/checks/MET-Teams014-CrossTenantAccess.md) | Cross-Tenant Guest & External Collaboration Restrictions | Medium | Entra cross-tenant access default policy and guest-invite authorization (Graph, degrades gracefully if unavailable) |
| [MET-Teams015](docs/checks/MET-Teams015-EmailIntegration.md) | Teams Email Integration | Medium | AllowEmailIntoChannel - channel email addresses accept external mail that never traverses the mailbox delivery path |

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

When `-OutputPath` is provided, MET creates a timestamped run folder and writes reports inside it (for example `./assessments/20260602-102530-contoso.onmicrosoft.com/`).

### Re-render a saved report

```powershell
Import-METReport -Path ./assessments/contoso-2026-06-01/MET-report.json |
    Get-METReport -Format HTML -OutputPath ./assessments/contoso-2026-06-01/
```

`Import-METReport` reads a JSON report `Get-METReport` previously wrote and rebuilds the original check-result objects, including the tenant and authentication provenance from that run - so a saved report can be re-rendered to console/HTML, compared against a later run, or filtered, without a live tenant connection or re-running the assessment.

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
