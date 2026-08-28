# MET Roadmap

Status legend: ✅ Done · 🔄 In Progress · 🗓 Planned · ❓ Under Investigation

---

## v0.1.0 - Core framework + MDO/EXO baseline ✅

| Item | Status |
|---|---|
| `New-METCheckResult` factory | ✅ |
| `Get-METCheckWeight` severity weights | ✅ |
| `Resolve-METPresetPolicy` helper | ✅ |
| `Connect-METSession` (EXO + Graph, interactive / SPN / MI) | ✅ |
| `Invoke-METTriage` (category / CheckId / ExcludeCheckId filters) | ✅ |
| `Get-METReport` - Console output | ✅ |
| `Get-METReport` - JSON output | ✅ |
| MDO001 Safe Links | ✅ |
| MDO002 Safe Attachments | ✅ |
| MDO003 Anti-Phishing | ✅ |
| MDO004 Anti-Spoofing | ✅ |
| MDO005 Anti-Malware | ✅ |
| MDO006 Anti-Spam Inbound | ✅ |
| MDO007 Anti-Spam Outbound | ✅ |
| MDO008 Preset Policy Coverage | ✅ |
| MDO009 Zero-Hour Auto Purge (ZAP) | ✅ |
| EXO001 DMARC | ✅ |
| EXO002 DKIM | ✅ |
| EXO003 SPF | ✅ |
| EXO004 Quarantine Policies | ✅ |
| Pester unit tests - factory + 3 MDO checks | ✅ |
| GitHub Actions - pester.yml (CI) | ✅ |
| GitHub Actions - publish.yml (PSGallery) | ✅ |

---

## v0.2.0 - Full check set + HTML report ✅

| Item | Status |
|---|---|
| MDO010 Priority Accounts | ✅ |
| MDO011 User Tags | ✅ |
| EXO005 Tenant Allow/Block List | ✅ |
| EXO006 Submission Policy | ✅ |
| EXO007 Transport Rule Audit | ✅ |
| Teams001 Safe Links for Teams | ✅ |
| Teams002 Safe Attachments for Teams | ✅ |
| Teams003 Meeting Protection | ✅ |
| `Connect-METSession` - MicrosoftTeams support (`-SkipTeams`) | ✅ |
| `Get-METReport` - HTML report (self-contained, offline-capable) | ✅ |
| HTML - Score banner + category scores | ✅ |
| HTML - Tabs: All / MDO / EXO / Teams / Accepted | ✅ |
| HTML - Live search + severity + result filters | ✅ |
| HTML - Check cards with collapse/expand | ✅ |
| HTML - "How to fix" accordion | ✅ |
| HTML - Accept Risk flow (localStorage) | ✅ |
| HTML - Top 5 Remediation Actions section | ✅ |
| HTML - Dark / light mode (prefers-color-scheme) | ✅ |
| Pester tests - EXO002, EXO004, EXO006 | ✅ |
| Pester tests - Teams001, Teams002, Teams003 | ✅ |
| docs/checks/ - 22 check documentation files | ✅ |
| docs/schema/MET-report-schema.json (JSON Schema draft-07) | ✅ |
| docs/CONTRIBUTING.md | ✅ |

---

## v0.3.0 - Quality, CI hardening, and usability ✅

| Item | Status | Notes |
|---|---|---|
| `Test-METPrerequisites` - checks module versions before triage | ✅ | Public function; returns structured results + coloured console output |
| Cross-platform DNS - `Resolve-METDnsName` private helper | ✅ | Windows: `Resolve-DnsName`; Linux/macOS: `dig` then `nslookup` fallback |
| EXO001 DMARC + EXO003 SPF use `Resolve-METDnsName` | ✅ | |
| PSScriptAnalyzer integration in CI (lint job before test job) | ✅ | `PSScriptAnalyzerSettings.psd1` at repo root; zero errors remaining |
| Fix `PSAvoidAssignmentToAutomaticVariable` - renamed `$Error` → `$ErrorMessage` | ✅ | All 19 check files + unit tests updated |
| CI workflow split into lint + test jobs (test depends on lint passing) | ✅ | |
| Pester integration tests with `Invoke-METTriage` (mocked) | ✅ | Stubs all EXO/Teams cmdlets; no live tenant required |
| `Invoke-METTriage -PassThru` - stream results as they complete | ✅ | Results written to pipeline per-check; useful for large tenants |
| `Invoke-METTriage -ListChecks` - dry-run that lists what would run | ✅ | Returns CheckId/Category/Script objects; respects all filters |
| Code coverage reporting in Pester CI | ✅ | JaCoCo XML via Pester `CodeCoverage`; integration tests run as separate step |

---

## v0.4.0 - Remaining check set, docs, and hardening ✅

| Item | Status | Notes |
|---|---|---|
| MDO012 Safe Documents | ✅ | `EnableSafeDocs` + `AllowSafeDocsOpen` via `Get-AtpPolicyForO365` |
| EXO008 Quarantine Retention | ✅ | `QuarantineRetentionPeriod` ≥ 30 days across all anti-spam policies |
| EXO009 Quarantine Policy Verdict Alignment | ✅ | Cross-references filter policies with their quarantine tags; warns on overly permissive tags for high-risk verdicts |
| Teams004 ZAP for Teams | ✅ | `TeamsProtectionPolicy.ZapEnabled`; malware and high-confidence phish quarantine tags |
| Teams005 Teams User Reporting | ✅ | `ReportTeamsMsgEnabled` + `AllowSecurityEndUserReporting` |
| MDO010 rewrite - `Get-EmailTenantSettings` + `Get-User -IsVIP` | ✅ | Removed Graph dependency; now checks the protection toggle and tag count separately |
| MDO011 rewrite - returns `Info` with portal link | ✅ | No reliable PowerShell cmdlet exists for tag enumeration; directs admin to Defender portal |
| `Get-METReport -Format All` - enforce `-OutputPath` | ✅ | Replaced `Write-Warning` with `$PSCmdlet.ThrowTerminatingError` (`InvalidArgument`); command terminates immediately if `-OutputPath` is omitted |
| README - Custom Policy Baseline (Promotions folder) | ✅ | Step-by-step guide with Strict-equivalent custom policies for all five protection types + `BulkMovesEnabled` |

---

## v0.5.0 - HTML report polish + security fix ✅

| Item | Status | Notes |
|---|---|---|
| HTML - Accepted tab (accepted risks move to their own tab) | ✅ | Closed a spec gap from v0.2.0 |
| HTML - Score donut + score-banded MDO/EXO/Teams meters | ✅ | |
| HTML - Inline code formatting for DNS/config values and PowerShell one-liners | ✅ | Applies to findings and recommendations |
| HTML - Sticky toolbar, print/export stylesheet, keyboard-accessible cards | ✅ | |
| HTML - localStorage fallback so the report renders on file:// pages where browsers block it | ✅ | |
| MET brand logo in HTML report header/favicon and README | ✅ | |
| Fix stored XSS in HTML report script-tag escaping | ✅ | #13 - untrusted check data (Finding/Recommendation/AffectedObject) could break out of the inline `<script>` JSON payload |

---

## v0.6.0 - Gap-closing checks across MDO/EXO/Teams mail-flow protection ✅

Gap analysis against Microsoft Learn found 11 concrete, checkable settings across the MDO/EOP mail-flow stack and Teams that the prior 26 checks didn't cover, plus 2 items needing further investigation before committing to a check ID. All 11 checks were implemented via parallel subagent dispatch (each check's `.ps1` + self-contained Pester test file + doc, no shared files touched, avoiding merge conflicts) and pass lint + the full 112-test suite with no regressions.

| Item | Status | Severity | Notes |
|---|---|---|---|
| EXO010 Direct Send / Anonymous Relay Exposure | ✅ | Critical | `Get-OrganizationConfig` → `RejectDirectSend`. Unauthenticated senders (and attackers, per Microsoft's 2025 advisory) can relay mail through the tenant's own MX and land as internal-looking spoofed mail, bypassing MDO004's anti-spoof checks entirely since the message never authenticates as external |
| EXO012 Mailbox Forwarding Exfiltration Risk | ✅ | Critical | `Get-EXOMailbox` `ForwardingSmtpAddress`/`ForwardingAddress`/`DeliverToMailboxAndForward`. Classic post-compromise BEC persistence; flags "silent" forwarding (no local copy retained) as the higher-risk pattern. Inbox-rule-based forwarding (`Get-InboxRule`) shipped out of scope as planned - doesn't scale to one API call per mailbox; remains a candidate for a future opt-in deeper scan |
| EXO011 Mail Flow Connector Hygiene | ✅ | High | `Get-InboundConnector`. Flags enabled connectors with `RequireTls=$false` or no effective sender IP/TLS certificate authentication binding; `SenderDomains` alone is not authentication. Outbound connectors shipped out of scope |
| EXO013 Spoof Intelligence Allow-List Hygiene | ✅ | High | `Get-TenantAllowBlockListSpoofItems -Action Allow`. MDO004 checks the `EnableSpoofIntelligence` toggle but not the accumulated allow-list content - a stale/broad allowed spoof pair is a standing phishing exception. Distinguishes Internal vs. External spoof type in the finding |
| MDO013 Preset vs. Custom Policy Precedence Conflicts | ✅ | High | Detects custom anti-spam, anti-malware, Anti-Phish, Safe Links, and Safe Attachments rules whose recipients are already covered by a higher-precedence Standard/Strict preset; fails closed if required data is incomplete |
| Teams006 External Access / Federation Allow-List | ✅ | High | `Get-CsTenantFederationConfiguration` (`AllowFederatedUsers`, `AllowedDomains`, `AllowTeamsConsumer`). Open federation (`AllowAllKnownDomains`) lets any external Teams/Skype user chat with staff - a common Teams phishing/vishing vector, and a separate control plane from Teams003's meeting-level external/anonymous join |
| EXO014 Advanced Delivery Policy Scope | ✅ | Medium | `Get-ExoPhishSimOverrideRule` and `Get-ExoSecOpsOverrideRule`. Surfaces enforceable phishing-simulation and SecOps mailbox bypass rules for periodic review |
| EXO015 External Sender Warning Tag | ✅ | Medium | `Get-ExternalInOutlook`. The native Outlook "External" banner is disabled by default; cheap, high-value, user-facing signal that's orthogonal to the message-level anti-phish/anti-spoof checks already in place |
| Teams007 Guest Messaging/Calling Configuration | ✅ | Medium | `Get-CsTeamsGuestMessagingConfiguration` / `Get-CsTeamsGuestCallingConfiguration`. Flags guest-initiated 1:1 chat and private calling; distinct from federation (Teams006) and meeting anonymous join (Teams003) |
| Teams008 App Permission Policy Exposure | ✅ | Medium | `Get-CsTeamsAppPermissionPolicy` (read-only; Microsoft restricts Set/New to admin center). Flags any `*CatalogAppsType` not restricted to an explicit `AllowedAppList`/`BlockedAppList`, detected by exclusion since the exact "unrestricted" enum value isn't confirmed in Microsoft's docs |
| EXO016 ARC Trusted Sealers Review | ✅ | Low (Info) | `Get-ArcConfig` → `ArcTrustedSealers`. Legitimate for mail-modifying gateways, but any listed domain is trusted to vouch for auth results, bypassing normal DMARC/DKIM checks for anything it seals. Informational - flags non-empty list for manual review, no "correct" value to assert |
| Enhancement: EXO001 DMARC alignment mode | 🗓 | - | Not yet done. Not a new check - extend EXO001 to also flag relaxed `aspf`/`adkim` alignment as a lower-strictness finding alongside the existing policy=quarantine/reject check. Deferred to bundle with the next release that touches EXO001 |

---

## v0.6.1 - Authentication fixes ✅

| Item | Status |
|---|---|
| Forward `-UseDeviceAuthentication` / `-UserPrincipalName` / `-DisableWAM` to the Teams leg | ✅ |
| Disable WAM automatically on non-Windows (MicrosoftTeams 7.9.0+ `kernel32.dll` failure) | ✅ |
| `Connect-MicrosoftTeams` certificate auth via `-Certificate` (`X509Store`), not `-CertificateThumbprint` | ✅ |
| `Connect-MicrosoftTeams` managed identity via `-Identity`, not `-ManagedIdentity` | ✅ |
| Surface actionable guidance when the Teams connection fails | ✅ |
| First unit test coverage for `Connect-METSession` | ✅ |
| Connect Exchange Online before Graph (Microsoft.Identity.Client load-order conflict) | ✅ |

---

## v0.7.0 - Optional Graph + group reference audit ✅

Follow-on to v0.6.1's auth work. Connect order alone cannot fix every MSAL collision - each Microsoft 365 module ships its own `Microsoft.Identity.Client` build and .NET cannot unload one once loaded - so Graph became an optional leg rather than a hard dependency, with Exchange Online fallbacks for every Graph call site.

| Item | Status | Notes |
|---|---|---|
| MDO014 Group Reference Audit | ✅ | New check. Flags groups referenced by enabled EOP/MDO rules via `SentToMemberOf`/`ExceptIfSentToMemberOf` that have 0 members (the condition matches nobody), and separately reports groups whose membership could not be resolved at all so a lookup failure is never reported as an empty group |
| Microsoft Graph is optional, not required | ✅ | A missing Graph module or a failed `Connect-MgGraph` warns and continues instead of aborting. `Test-METPrerequisites` marks both Graph modules optional |
| `Expand-METGroupMembership` Exchange Online fallback | ✅ | `Get-DistributionGroupMember` for distribution and mail-enabled security groups, `Get-UnifiedGroupLinks` for Microsoft 365 Groups - covering every group type EOP/MDO policies can target |
| MSAL assembly-conflict pre-flight detection | ✅ | `Test-METAssemblyLoadConflict` reports an actionable message instead of MSAL's opaque 0x80131040 manifest mismatch. Only a genuine downgrade (loaded version older than required) is a conflict - .NET resolves an older-or-equal request against a newer loaded assembly |
| `Import-Module MicrosoftTeams` failures are non-fatal | ✅ | Moved inside the Teams leg's `try/catch` so an import failure warns and continues, like every other Teams failure |
| Aggregate `Info`-only results in default output | ✅ | Multiple `Info` results for one CheckId are now summarised rather than truncated to the first item (affected MDO014, EXO013/014/016) |

---

## v0.8.0 - Teams attack-surface hardening ✅

Gap analysis triggered by an external check-suggestions draft against MET's 8 shipped Teams checks. Found 5 genuinely new, checkable settings plus 5 real gaps in existing checks (including one pre-existing blind spot: Teams003 only ever evaluated the `Global` meeting policy), and confirmed one item researched by the user (AIR auto-remediation) has no supported API surface at all and won't become a check. All 5 new checks + 5 enhancements implemented via parallel subagent dispatch (each on disjoint files); full suite passes 261/261 tests with zero lint errors, no regressions.

| Item | Status | Severity | Notes |
|---|---|---|---|
| Teams009 Trial Tenant Federation Exposure | ✅ | High | New check. `Get-CsTenantFederationConfiguration` → `ExternalAccessWithTrialTenants` (string enum `Allowed`/`Blocked`, not boolean - draft correctly flagged this as unconfirmed) |
| Teams010 Per-User External Access Policy Drift | ✅ | Medium | New check. `Get-CsExternalAccessPolicy` enumerated across all non-Global instances. Only `EnableFederationAccess`/`EnablePublicCloudAccess` are Learn-confirmed properties; needs a live-tenant property dump before the Fail condition is finalized |
| Teams011 SecOps Blocklist Authority & Blocked Entities | ✅ | Medium (Warning) | New check. `SecurityTeamAllowBlockListDelegation` on `Get-CsTenantFederationConfiguration` (draft guessed the wrong cmdlet for this) + `Get-CsTeamsExternalAccessConfiguration` for currently-blocked entities |
| Teams012 Call Reporting (Vishing Surface) | ✅ | Medium | New check. `Get-CsTeamsCallingPolicy` → `ReportCall` (string, not boolean) |
| Teams014 Cross-Tenant Guest & External Collaboration | ✅ | Medium | New check, first direct Graph call from a check body (not via `Expand-METGroupMembership`). `GET /policies/crossTenantAccessPolicy` + `/policies/authorizationPolicy`, confirmed to need only the already-requested `Policy.Read.All` scope. Must degrade to `NotApplicable` non-fatally if Graph is unavailable |
| Enhancement: Teams001 Safe Links rule-targeting | ✅ | - | Verify a `Get-SafeLinksRule` actually assigns each policy with `EnableSafeLinksForTeams=$true` - a flagged-on policy with no assigning rule isn't applied |
| Enhancement: Teams003 meeting policy enumeration | ✅ | - | Fixes a real gap: currently filters to `Identity -eq 'Global'` only, so custom meeting policies are invisible. Also adds `AllowPSTNUsersToBypassLobby` |
| Enhancement: Teams004 ZAP rule scope | ✅ | - | Add `Get-TeamsProtectionPolicyRule` check so rule-level exceptions/exclusions aren't invisible to the existing policy-level ZAP check |
| Enhancement: Teams006 federation properties | ✅ | - | Add `AllowTeamsConsumerInbound`, `RestrictTeamsConsumerToExternalUserProfiles`, and `BlockedDomains`-emptiness to the existing federation check |
| Enhancement: Teams008 ACM caveat | ✅ | - | Doc-only `Recommendation` caveat that legacy app permission policies may be inert on ACM-migrated tenants - no cmdlet exists yet to detect migration state itself, so no code-logic change |
| AIR auto-remediation - documented, not a check | ✅ | - | Confirmed no supported cmdlet or public Graph API exists to read/set AIR auto-remediation settings; adding a "Manual Review Items" section to README instead of a synthetic always-static check |

---

## v0.9.0 - Quarantine policy accuracy pass ✅

Design conversation about quarantine checks not distinguishing Microsoft-managed preset (Standard/Strict) configuration from admin-managed custom configuration surfaced two confirmed false-positive bugs, not just a design gap. All 4 items implemented via parallel subagent dispatch; full suite passes 292/292 tests with zero lint errors, no regressions.

| Item | Status | Severity | Notes |
|---|---|---|---|
| Shared helper: preset/built-in policy name detection | ✅ | - | `Private/Test-METIsPresetSecurityPolicyName.ps1` - `Test-METIsPresetSecurityPolicyName` (Strict/Standard preset filter policies) and `Test-METIsBuiltInQuarantinePolicyName` (the 4 built-in quarantine policies), reused across EXO004/008/009 |
| Fix: MET-EXO009 verdict risk model | ✅ | High | Confirmed bug: the old risk model flagged Microsoft's own Strict preset impersonation/phish/spoof quarantine tags as Fail/Warning, since those verdicts use Full-access policies even under Strict. Corrected to a fixed restricted set (Malware, High-Confidence Phish only) and skips preset-generated policy objects entirely |
| Fix: MET-EXO004 false-positive on AdminOnlyAccessPolicy | ✅ | Medium | Confirmed bug: flagged every tenant's `AdminOnlyAccessPolicy` (No access, by design) as a misconfiguration on every run. Narrowed to reviewing genuinely custom quarantine policies for a notification/permission mismatch, excluding all 4 built-ins |
| Enhancement: MET-EXO008 preset-aware retention | ✅ | - | Skips an actionable `Set-HostedContentFilterPolicy` recommendation against Standard/Strict preset policies (not editable, would error); notes that this same setting governs anti-phishing (spoof/impersonation) quarantine retention too |
| New: MET-EXO017 Quarantine Notification Cadence | ✅ | Informational | `EndUserSpamNotificationFrequency` on the global quarantine policy (`DefaultGlobalTag`) - Info-only, no Microsoft-recommended value exists |

---

## v0.10.0 - Connect-METSession security hardening ✅

A hardening proposal for `Connect-METSession` surfaced a confirmed cross-customer data leak path plus five supporting fixes. Every technical claim was independently verified against the actual code before acceptance (not taken on trust), and the device-code phishing risk claim was independently researched against current Microsoft guidance. Implemented and verified: full suite passes 315/315 unit + 16/16 integration tests with zero lint errors, no regressions (also caught and fixed a pre-existing stale integration test asserting a 38-check count instead of the current 44).

| Item | Status | Severity | Notes |
|---|---|---|---|
| Tenant-scoped session reuse | ✅ | Critical | Confirmed bug: all three legs (EXO/Graph/Teams) reuse any live connection with zero tenant/org comparison - the Teams leg even logs the connected tenant ID without ever checking it. A consultant running MET against two `-DelegatedOrganization` customers back-to-back in one session without disconnecting gets a report labeled customer B containing customer A's actual configuration |
| New: `Disconnect-METSession` | ✅ | - | Per-leg try/catch teardown (EXO/Graph/Teams), added to `FunctionsToExport`. Ships with item 1 since its error message names this function |
| Certificate-file auth (`-CertificatePath`/`-CertificatePassword`) | ✅ | - | `ServicePrincipal` set is X509Store/thumbprint-only today, which is Windows-only in practice - the actual reason device code became the Codespaces auth path. Makes the tightened device-code guidance (below) honest on Linux |
| Scope device-code guidance down | ✅ | High | Confirmed: 4 failure paths currently suggest `-UseDeviceAuthentication` as the generic retry. Research confirmed Microsoft's own current guidance is *stronger* than the source proposal: "block wherever possible... allow only where necessary" (Storm-2372 and follow-on campaigns through April 2026 are live, not historical). Scope to a documented headless-only fallback, warn on use, never suggest as first-line retry |
| Record auth method in the report | ✅ | - | Surfaces auth mode/tenant/connected services in the `Get-METReport` header, so a customer's SOC can reconcile a `deviceCodeFlow` sign-in with a known MET run instead of triaging it as an incident. Lowest urgency of the six, can defer if scope needs trimming |
| Fix README/code contradiction | ✅ | - | README claims device auth is needed for any Linux/macOS + Teams 7.9+; code already auto-applies `-DisableWAM` off-Windows (`Connect-METSession.ps1:228`), which resolves the actual failure. Narrow the doc to the genuine case - no browser reachable at all - after re-testing in a Codespace with `-DisableWAM` alone |
| Real-tenant validation of `-CertificatePath` | ✅ | Medium | Setting up cert-based auth end-to-end in a live Codespace surfaced two real `Connect-METSession` bugs the unit tests (all mocked) couldn't catch, both now fixed with regression tests: (1) a GUID `-TenantId` reaches `Connect-ExchangeOnline -Organization`, which rejects GUIDs outright - now fails fast with an actionable error before attempting to connect; (2) `-CertificatePath` was forwarded verbatim to the module's own `File.Exists()` validation, which - confirmed by decompiling `ExchangeOnlineManagement`'s `ValidateCertificatePath` method - never expands `~` or resolves a relative path; `Connect-METSession` now resolves it to an absolute path up front. Also corrected README's service-principal setup: it was missing the `Exchange.ManageAsApp` API permission (a separate, mandatory requirement from any RBAC role - its absence produces a generic `UnAuthorized` with no clue what's missing) and gave an `Add-RoleGroupMember -Identity 'Security Reader'` command that fails on tenants where that role group is centrally synced from the Entra ID `Security reader` directory role and not directly manageable via Exchange RBAC |

---

## v0.11.0 - Mail-flow, auth-surface and audit coverage ✅

Seven new checks and three enhancements to existing checks, closing gaps in control planes MET could previously see no state for at all. Every new check is standalone (own file, own self-contained test file, own docs page); no existing check's result, severity or wording was changed. Verified with zero lint findings and a full green suite.

| Item | Status | Severity | Notes |
|---|---|---|---|
| EXO018 Remote Domain Automatic Forwarding | ✅ | High | The third forwarding control plane. MET already assessed the outbound spam policy's `AutoForwardingMode` (MDO007) and per-mailbox forwarding (EXO012), but never `Get-RemoteDomain`'s `AutoForwardEnabled` - so a tenant whose default `*` remote domain permits auto-forward to every external domain scored clean on forwarding. One result per remote domain; the wildcard domain is a Fail, a specific domain a Warning |
| EXO019 SMTP Client Authentication | ✅ | High | Legacy SMTP AUTH is a basic-authentication endpoint largely exempt from conditional access and a standing password-spray target. Checks the tenant-wide switch, then - only when that is already closed - enumerates per-mailbox overrides that re-open it. The enumeration has its own try/catch and degrades to a Pass with the error surfaced, so a mailbox-enumeration failure can never abort the check |
| EXO020 Connection Filter Policy Hygiene | ✅ | High | `IPAllowList` entries skip spam filtering *and* spoof intelligence, so an attacker relaying through any listed host inherits a trusted path into every mailbox. Broad IPv4 CIDR ranges are called out separately; unparseable, range-form and IPv6 entries are skipped rather than guessed at. `EnableSafeList` is a Warning because its contents cannot be enumerated from PowerShell and therefore cannot be reviewed |
| EXO021 Mailbox Audit Logging | ✅ | Medium | `AuditDisabled` has an inverted sense (`$true` = auditing off), which is the obvious way to get this check backwards - a dedicated regression test asserts Fail only on `$true` and Pass only on `$false`. An absent property is Pass-with-assumption, since Microsoft's platform default is on |
| EXO022 Calendar and Contact Sharing | ✅ | Medium | Calendar detail or contacts shared with `*`/`Anonymous` hands an attacker the org chart, meeting subjects, attendee lists and internal addresses that an internal-impersonation phish is built from. Free/busy-simple to `*` passes explicitly; disabled policies report Info rather than Pass |
| EXO023 Unified Audit Log Ingestion | ✅ | High | Unlike EXO021, an absent property is a Fail rather than an assumed default, because ingestion has shipped switched off in some tenants. Retention duration is explicitly **not** asserted - it needs a Purview connection this module deliberately does not open - and is documented as a manual follow-up rather than silently implied |
| Teams015 Teams Email Integration | ✅ | Medium | Channel email addresses accept mail from outside the organisation and deliver it into the channel rather than a mailbox, so Exchange transport rules and mailbox-level policy never apply - a delivery route that bypasses the mail path the rest of the module assesses. Warning rather than Fail, since the feature is legitimate and has a per-team sender restriction as the middle ground |
| MDO005 enhancement: attachment filter contents | ✅ | - | The check asserted the common attachment filter was enabled but never looked inside it. A filter that is on with a list omitting the formats actually used to deliver payloads gives false assurance, so the extension list is now compared against a high-risk set and missing entries reported as one issue line |
| MDO003 enhancement: partner domain impersonation | ✅ | - | Covered targeted users and the tenant's own accepted domains, but not explicitly-named external domains - which are the ones abused in invoice-redirection and payment-diversion fraud. Now reads `EnableTargetedDomainsProtection`/`TargetedDomainsToProtect` |
| Teams003 enhancement: two meeting properties | ✅ | - | `AllowExternalParticipantGiveRequestControl` (the screen-control handoff used in remote-access social engineering) and `AllowAnonymousUsersToStartMeeting` (which defeats lobby controls that assume an organiser admits attendees), across all meeting policies |
| HTML report defect: embedded check array collapsed | ✅ | High | Found by the new tests, not by inspection. `ConvertTo-Json` does not preserve array-ness for 0- or 1-element collections, so a single-check run emitted `const CHECKS = {...}` (`CHECKS.slice is not a function`) and an empty run emitted `const CHECKS = ;` (`Unexpected token ';'`). Either killed the entire report script: no cards, no score, no filters, no tabs - a blank shell from a normal `Invoke-METTriage -CheckId ... | Get-METReport -Format HTML` run. The same collapse made the JSON output emit `checks` as an object rather than an array, violating `docs/schema/MET-report-schema.json`. Both sites now materialise the collection first; the HTML path emits a literal `[]` when empty, since `-AsArray` produces no output at all for an empty pipeline |
| HTML report defect: unreachable version fallback | ✅ | Low | `(Get-Module MET)?.Version.ToString() ?? '0.2.0'` - the null-conditional guards only `Version`, so `.ToString()` ran on `$null` and threw before the fallback could apply. The hardcoded fallback had also drifted nine minor versions out of date. Replaced with a helper that reads the loaded module, falls back to the manifest on disk, and cannot go stale |
| HTML report test coverage | ✅ | - | The report had no automated coverage of its own markup or behaviour. Added string-level Pester assertions (self-contained/offline guarantee, injection safety in both the rendered-markup and embedded-JSON paths, unsafe-URI handling, empty and single-Info result sets) plus a browser-driven suite covering tab switching, live search, combined filters, the accept-risk flow and its persistence, and card expansion |

---

## Under Investigation ❓

| Item | Status | Notes |
|---|---|---|
| Attack Simulation Training coverage | ❓ | Graph beta `securityReportsRoot/getAttackSimulationTrainingUserCoverage` (permission `AttackSimulation.Read.All`). Real gap - MDO's technical controls don't compensate for an untrained user base - but requires an additive Graph scope beyond MET's current `Identity.SignIns`/`Groups`, and the beta endpoint isn't GA. Needs a decision on whether to expand `Connect-METSession`'s Graph scope set before this becomes a committed check |
| Secure Score correlation | ❓ | `Get-MgSecuritySecureScore` (Microsoft.Graph.Security - not currently a MET dependency). Informational cross-reference only, not a pass/fail check; lowest priority, would add a new module dependency for a "nice to have" dashboard signal |
| Risky Teams app/bot catalog enumeration | ❓ | Graph `GET /appCatalogs/teamsApps` confirmed working, but needs `AppCatalog.Read.All` - not in MET's current Graph scope set. Same scope-expansion decision as Attack Simulation Training above |
| ACM (App Centric Management) migration-state detection | ❓ | No confirmed cmdlet or Graph property reads whether a tenant has migrated to ACM, so Teams008 can't reliably distinguish a compliant legacy policy from an inert one. Revisit if Microsoft documents a detection surface |
| Org-wide third-party app enablement / sideloading toggle | ❓ | No confirmed Graph endpoint for this specific org-wide toggle; it currently lives only in Teams admin center |

---

## Known issues / by design

| Item | Details |
|---|---|
| Teams003 cmdlet availability - by design | `Get-CsTenantFederationConfiguration` and `Get-CsTeamsMeetingPolicy` require the MicrosoftTeams module. Each call is wrapped in `try/catch`; failures are logged via `Write-Verbose` and the check continues silently. No result object is emitted for the missing data - this is intentional. |
