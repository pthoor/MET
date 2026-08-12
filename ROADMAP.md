# MET Roadmap

Status legend: ✅ Done · 🔄 In Progress · 🗓 Planned · ❓ Under Investigation

---

## v0.1.0 — Core framework + MDO/EXO baseline ✅

| Item | Status |
|---|---|
| `New-METCheckResult` factory | ✅ |
| `Get-METCheckWeight` severity weights | ✅ |
| `Resolve-METPresetPolicy` helper | ✅ |
| `Connect-METSession` (EXO + Graph, interactive / SPN / MI) | ✅ |
| `Invoke-METTriage` (category / CheckId / ExcludeCheckId filters) | ✅ |
| `Get-METReport` — Console output | ✅ |
| `Get-METReport` — JSON output | ✅ |
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
| Pester unit tests — factory + 3 MDO checks | ✅ |
| GitHub Actions — pester.yml (CI) | ✅ |
| GitHub Actions — publish.yml (PSGallery) | ✅ |

---

## v0.2.0 — Full check set + HTML report ✅

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
| `Connect-METSession` — MicrosoftTeams support (`-SkipTeams`) | ✅ |
| `Get-METReport` — HTML report (self-contained, offline-capable) | ✅ |
| HTML — Score banner + category scores | ✅ |
| HTML — Tabs: All / MDO / EXO / Teams / Accepted | ✅ |
| HTML — Live search + severity + result filters | ✅ |
| HTML — Check cards with collapse/expand | ✅ |
| HTML — "How to fix" accordion | ✅ |
| HTML — Accept Risk flow (localStorage) | ✅ |
| HTML — Top 5 Remediation Actions section | ✅ |
| HTML — Dark / light mode (prefers-color-scheme) | ✅ |
| Pester tests — EXO002, EXO004, EXO006 | ✅ |
| Pester tests — Teams001, Teams002, Teams003 | ✅ |
| docs/checks/ — 22 check documentation files | ✅ |
| docs/schema/MET-report-schema.json (JSON Schema draft-07) | ✅ |
| docs/CONTRIBUTING.md | ✅ |

---

## v0.3.0 — Quality, CI hardening, and usability ✅

| Item | Status | Notes |
|---|---|---|
| `Test-METPrerequisites` — checks module versions before triage | ✅ | Public function; returns structured results + coloured console output |
| Cross-platform DNS — `Resolve-METDnsName` private helper | ✅ | Windows: `Resolve-DnsName`; Linux/macOS: `dig` then `nslookup` fallback |
| EXO001 DMARC + EXO003 SPF use `Resolve-METDnsName` | ✅ | |
| PSScriptAnalyzer integration in CI (lint job before test job) | ✅ | `PSScriptAnalyzerSettings.psd1` at repo root; zero errors remaining |
| Fix `PSAvoidAssignmentToAutomaticVariable` — renamed `$Error` → `$ErrorMessage` | ✅ | All 19 check files + unit tests updated |
| CI workflow split into lint + test jobs (test depends on lint passing) | ✅ | |
| Pester integration tests with `Invoke-METTriage` (mocked) | ✅ | Stubs all EXO/Teams cmdlets; no live tenant required |
| `Invoke-METTriage -PassThru` — stream results as they complete | ✅ | Results written to pipeline per-check; useful for large tenants |
| `Invoke-METTriage -ListChecks` — dry-run that lists what would run | ✅ | Returns CheckId/Category/Script objects; respects all filters |
| Code coverage reporting in Pester CI | ✅ | JaCoCo XML via Pester `CodeCoverage`; integration tests run as separate step |

---

## v0.4.0 — Remaining check set, docs, and hardening ✅

| Item | Status | Notes |
|---|---|---|
| MDO012 Safe Documents | ✅ | `EnableSafeDocs` + `AllowSafeDocsOpen` via `Get-AtpPolicyForO365` |
| EXO008 Quarantine Retention | ✅ | `QuarantineRetentionPeriod` ≥ 30 days across all anti-spam policies |
| EXO009 Quarantine Policy Verdict Alignment | ✅ | Cross-references filter policies with their quarantine tags; warns on overly permissive tags for high-risk verdicts |
| Teams004 ZAP for Teams | ✅ | `TeamsProtectionPolicy.ZapEnabled`; malware and high-confidence phish quarantine tags |
| Teams005 Teams User Reporting | ✅ | `ReportTeamsMsgEnabled` + `AllowSecurityEndUserReporting` |
| MDO010 rewrite — `Get-EmailTenantSettings` + `Get-User -IsVIP` | ✅ | Removed Graph dependency; now checks the protection toggle and tag count separately |
| MDO011 rewrite — returns `Info` with portal link | ✅ | No reliable PowerShell cmdlet exists for tag enumeration; directs admin to Defender portal |
| `Get-METReport -Format All` — enforce `-OutputPath` | ✅ | Replaced `Write-Warning` with `$PSCmdlet.ThrowTerminatingError` (`InvalidArgument`); command terminates immediately if `-OutputPath` is omitted |
| README — Custom Policy Baseline (Promotions folder) | ✅ | Step-by-step guide with Strict-equivalent custom policies for all five protection types + `BulkMovesEnabled` |

---

## v0.5.0 — HTML report polish + security fix ✅

| Item | Status | Notes |
|---|---|---|
| HTML — Accepted tab (accepted risks move to their own tab) | ✅ | Closed a spec gap from v0.2.0 |
| HTML — Score donut + score-banded MDO/EXO/Teams meters | ✅ | |
| HTML — Inline code formatting for DNS/config values and PowerShell one-liners | ✅ | Applies to findings and recommendations |
| HTML — Sticky toolbar, print/export stylesheet, keyboard-accessible cards | ✅ | |
| HTML — localStorage fallback so the report renders on file:// pages where browsers block it | ✅ | |
| MET brand logo in HTML report header/favicon and README | ✅ | |
| Fix stored XSS in HTML report script-tag escaping | ✅ | #13 — untrusted check data (Finding/Recommendation/AffectedObject) could break out of the inline `<script>` JSON payload |

---

## v0.6.0 — Planned 🗓

Gap analysis against Microsoft Learn (see `docs/gap-analysis-2026-08.md` for full research notes) found 11 concrete, checkable settings across the MDO/EOP mail-flow stack and Teams that the current 26 checks don't cover, plus 2 items needing further investigation before committing to a check ID. Grouped and prioritized below; see the phased implementation plan after this table.

| Item | Status | Severity | Notes |
|---|---|---|---|
| EXO010 Direct Send / Anonymous Relay Exposure | 🗓 | Critical | `Get-OrganizationConfig` → `RejectDirectSend`. Unauthenticated senders (and attackers, per Microsoft's 2025 advisory) can relay mail through the tenant's own MX and land as internal-looking spoofed mail, bypassing MDO004's anti-spoof checks entirely since the message never authenticates as external |
| EXO012 Mailbox Forwarding & Inbox Rule Exfiltration | 🗓 | Critical | `Get-EXOMailbox -Properties ForwardingSmtpAddress,DeliverToMailboxAndForward` (+ `Get-InboxRule` forwarding actions, scoping TBD — see implementation plan). Classic post-compromise BEC persistence; MDO007 only checks the tenant-wide auto-forward toggle, not per-mailbox forwarding |
| EXO011 Mail Flow Connector Hygiene | 🗓 | High | `Get-InboundConnector` / `Get-OutboundConnector`. Inbound connectors with `RequireTls=$false` or no sender restriction accept anonymous/opportunistic-TLS mail that can be treated as internal; nothing today inspects connectors at all |
| EXO013 Spoof Intelligence Allow-List Hygiene | 🗓 | High | `Get-TenantAllowBlockListSpoofItems -Action Allow`. MDO004 checks the `EnableSpoofIntelligence` toggle but not the accumulated allow-list content — a stale/broad allowed spoof pair is a standing phishing exception |
| MDO013 Preset vs. Custom Policy Precedence Conflicts | 🗓 | High | Extends MDO008's cmdlets (`Get-AntiPhishPolicy`, `Get-HostedContentFilterPolicy`, rule priorities) to detect recipients shadowed by a weaker custom policy losing precedence to (or silently overridden by) a preset policy — a distinct failure mode from MDO008's coverage-gap check |
| Teams006 External Access / Federation Allow-List | 🗓 | High | `Get-CsTenantFederationConfiguration` (`AllowFederatedUsers`, `AllowedDomains`, `AllowTeamsConsumer`). Open federation lets any external Teams/Skype user chat with staff — a common Teams phishing/vishing vector, and a separate control plane from Teams003's meeting-level external/anonymous join |
| EXO014 Advanced Delivery Policy Scope | 🗓 | Medium | `Get-PhishSimOverridePolicy` / `Get-ExoPhishSimOverrideRule`. Legitimate for phishing-sim platforms and SecOps mailboxes, but a stale or overly broad entry (wildcard domain, huge IP range) is an unfiltered inbound channel that bypasses MDO entirely |
| EXO015 External Sender Warning Tag | 🗓 | Medium | `Get-ExternalInOutlook`. The native Outlook "External" banner is disabled by default; cheap, high-value, user-facing signal that's orthogonal to the message-level anti-phish/anti-spoof checks already in place |
| Teams007 Guest Messaging/Calling Configuration | 🗓 | Medium | `Get-CsTeamsGuestMessagingConfiguration` / `Get-CsTeamsGuestCallingConfiguration`. Persistent guest membership with unrestricted messaging/calling widens social-engineering surface; distinct from federation (external tenants) and meeting anonymous join |
| Teams008 App Permission Policy Exposure | 🗓 | Medium | `Get-CsTeamsAppPermissionPolicy` (read-only; Microsoft restricts Set/New to admin center). Flags a default "allow all apps" assignment — third-party Teams apps with delegated Graph permissions are a growing OAuth-consent-phishing vector |
| EXO016 ARC Trusted Sealers Review | 🗓 | Low (Info) | `Get-ArcConfig` → `ArcTrustedSealers`. Legitimate for mail-modifying gateways, but any listed domain is trusted to vouch for auth results, bypassing normal DMARC/DKIM checks for anything it seals. Informational — flags non-empty list for manual review, no "correct" value to assert |
| Enhancement: EXO001 DMARC alignment mode | 🗓 | — | Not a new check — extend EXO001 to also flag relaxed `aspf`/`adkim` alignment as a lower-strictness finding alongside the existing policy=quarantine/reject check |

---

## Under Investigation ❓

| Item | Status | Notes |
|---|---|---|
| Attack Simulation Training coverage | ❓ | Graph beta `securityReportsRoot/getAttackSimulationTrainingUserCoverage` (permission `AttackSimulation.Read.All`). Real gap — MDO's technical controls don't compensate for an untrained user base — but requires an additive Graph scope beyond MET's current `Identity.SignIns`/`Groups`, and the beta endpoint isn't GA. Needs a decision on whether to expand `Connect-METSession`'s Graph scope set before this becomes a committed check |
| Secure Score correlation | ❓ | `Get-MgSecuritySecureScore` (Microsoft.Graph.Security — not currently a MET dependency). Informational cross-reference only, not a pass/fail check; lowest priority, would add a new module dependency for a "nice to have" dashboard signal |

---

## Known issues / by design

| Item | Details |
|---|---|
| Teams003 cmdlet availability — by design | `Get-CsTenantFederationConfiguration` and `Get-CsTeamsMeetingPolicy` require the MicrosoftTeams module. Each call is wrapped in `try/catch`; failures are logged via `Write-Verbose` and the check continues silently. No result object is emitted for the missing data — this is intentional. |
