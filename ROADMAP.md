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

## v0.5.0 — Planned 🗓

| Item | Status | Notes |
|---|---|---|
| Signed module release | 🗓 | Code-signing certificate for PSGallery publication |

---

## Known issues / by design

| Item | Details |
|---|---|
| Teams003 cmdlet availability — by design | `Get-CsTenantFederationConfiguration` and `Get-CsTeamsMeetingPolicy` require the MicrosoftTeams module. Each call is wrapped in `try/catch`; failures are logged via `Write-Verbose` and the check continues silently. No result object is emitted for the missing data — this is intentional. |
