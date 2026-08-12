# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# MET — Security Posture Scanner for MDO, EXO and Teams

> Open-source PowerShell module for assessing Microsoft Defender for Office 365 (MDO), Exchange Online (EOP), and Microsoft Teams protection posture.

---

## Mission

MET assesses the security posture of an M365 tenant across MDO, EXO/EOP, and Teams threat protection. It produces structured, machine-readable output (PSCustomObject / JSON) suitable for human review, CI/CD gates, SIEM ingestion, and dashboards. It is not a replacement for the built-in MDO Configuration Analyzer — it goes further: Teams protection, email authentication, quarantine policy hygiene, per-user coverage gaps, and Tenant Allow/Block List hygiene.

Comparable tools for context:
- **ORCA** (cammurray/orca) — MDO/EOP HTML report, no Teams, no structured output, showing its age
- **MDOThreatPolicyChecker** (microsoft/CSS-Exchange) — per-user policy resolution only, not a posture assessment

---

## Repository Layout

```
MET/
├── MET.psd1                         # Module manifest
├── MET.psm1                         # Module root — dot-sources Public/ and Private/
├── Public/
│   ├── Invoke-METTriage.ps1         # Main entry point — runs all or selected checks
│   ├── Get-METReport.ps1            # Formats and exports results (console / JSON / HTML)
│   ├── Connect-METSession.ps1       # Handles EXO + Teams + Graph auth
│   └── Test-METPrerequisites.ps1    # Verifies required module versions before triage
├── Private/
│   ├── New-METCheckResult.ps1       # Factory for the standard check result object
│   ├── Get-METCheckWeight.ps1       # Returns severity weight for scoring
│   ├── Get-METRuleScope.ps1         # Formats rule scope label for check findings
│   ├── Resolve-METPresetPolicy.ps1  # Helper: resolves preset policy membership
│   ├── Resolve-METCoverageMatrix.ps1 # Builds per-mailbox policy coverage matrix
│   ├── Resolve-METDnsName.ps1       # DNS lookup wrapper used by EXO email auth checks
│   ├── Expand-METRuleRecipients.ps1 # Expands rule recipient conditions to mailbox lists
│   ├── Expand-METGroupMembership.ps1 # Resolves distribution/security group members
│   └── Find-METRuleContradictions.ps1 # Detects conflicting transport rule conditions
├── Checks/
│   ├── MDO/
│   │   ├── MET-MDO001-SafeLinks.ps1
│   │   ├── MET-MDO002-SafeAttachments.ps1
│   │   ├── MET-MDO003-AntiPhish.ps1
│   │   ├── MET-MDO004-AntiSpoofing.ps1
│   │   ├── MET-MDO005-AntiMalware.ps1
│   │   ├── MET-MDO006-AntiSpamInbound.ps1
│   │   ├── MET-MDO007-AntiSpamOutbound.ps1
│   │   ├── MET-MDO008-PresetPolicyCoverage.ps1
│   │   ├── MET-MDO009-ZAP.ps1
│   │   ├── MET-MDO010-PriorityAccounts.ps1
│   │   ├── MET-MDO011-UserTags.ps1
│   │   └── MET-MDO012-SafeDocuments.ps1
│   ├── EXO/
│   │   ├── MET-EXO001-DMARC.ps1
│   │   ├── MET-EXO002-DKIM.ps1
│   │   ├── MET-EXO003-SPF.ps1
│   │   ├── MET-EXO004-QuarantinePolicy.ps1
│   │   ├── MET-EXO005-TenantAllowBlockList.ps1
│   │   ├── MET-EXO006-SubmissionPolicy.ps1
│   │   ├── MET-EXO007-TransportRuleAudit.ps1
│   │   ├── MET-EXO008-QuarantineRetention.ps1
│   │   └── MET-EXO009-QuarantinePolicyVerdictAlignment.ps1
│   └── Teams/
│       ├── MET-Teams001-SafeLinks.ps1
│       ├── MET-Teams002-SafeAttachments.ps1
│       ├── MET-Teams003-MeetingProtection.ps1
│       ├── MET-Teams004-ZAPForTeams.ps1
│       └── MET-Teams005-TeamsUserReporting.ps1
├── Tests/
│   ├── Unit/
│   │   ├── New-METCheckResult.Tests.ps1
│   │   ├── Resolve-METCoverageMatrix.Tests.ps1
│   │   ├── Checks.MDO.Tests.ps1
│   │   ├── Checks.EXO.Tests.ps1
│   │   └── Checks.Teams.Tests.ps1
│   └── Integration/
│       └── Invoke-METTriage.Tests.ps1
├── docs/
│   ├── checks/                       # One .md per check describing what it tests and why
│   └── CONTRIBUTING.md
├── .github/
│   ├── dependabot.yml                # Weekly updates for GitHub Actions pins
│   └── workflows/
│       ├── pester.yml                # Lint + Pester on PR and push to main
│       └── publish.yml               # Publish to PSGallery on tag
├── LICENSE                           # MIT
└── README.md
```

---

## Tech Stack

| Requirement | Detail |
|---|---|
| PowerShell | 7.4+ (tested on 7.4, 7.6) |
| ExchangeOnlineManagement | 3.9+ (modern auth, REST-based) — required |
| Microsoft.Graph.Identity.SignIns / .Groups | 2.x — required |
| MicrosoftTeams | 6.x+ (latest 7.x) — optional; Teams checks skip gracefully if absent |
| Pester | 5.x for all tests |

No Python. No ARM. No Terraform. No legacy Basic Auth. Full support is Windows-only — on Linux/macOS every check runs except EXO001 (DMARC) and EXO003 (SPF), which need `Resolve-DnsName`; `Resolve-METDnsName` falls back to `dig`/`nslookup` there.

`RequiredModules` is deliberately empty in `MET.psd1` — declaring them there causes a hard import failure when a dependency is missing, which would prevent `Test-METPrerequisites` from running and guiding the user. Dependencies are checked at runtime instead.

---

## Development Commands

```powershell
# Import the module locally (no build step — this is a pure PowerShell script module)
Import-Module ./MET.psd1 -Force

# Lint (matches CI's lint job exactly — must be zero errors)
Install-Module PSScriptAnalyzer -MinimumVersion 1.21.0 -Scope CurrentUser
Invoke-ScriptAnalyzer -Path Public,Private,Checks -Recurse -Settings ./PSScriptAnalyzerSettings.psd1

# Unit tests (no tenant connection required — all EXO/Graph/Teams cmdlets are mocked)
$config = New-PesterConfiguration
$config.Run.Path = './Tests/Unit'
$config.Output.Verbosity = 'Detailed'
Invoke-Pester -Configuration $config

# Run a single test file
Invoke-Pester -Path ./Tests/Unit/Checks.MDO.Tests.ps1 -Output Detailed

# Run a single test by name
Invoke-Pester -Path ./Tests/Unit -FullNameFilter '*MET-EXO001*' -Output Detailed

# Integration tests (also mocked — no live tenant required)
Invoke-Pester -Path ./Tests/Integration -Output Detailed
```

CI (`pester.yml`) runs three jobs in order: `lint` (PSScriptAnalyzer, zero errors required) → `test` (unit tests with a 30% JaCoCo coverage gate, then integration tests) → `credential-scan` (TruffleHog). Lint failures block the test job.

---

## Coding Conventions

- **Approved verbs only** — `Invoke-`, `Get-`, `Test-`, `Connect-`, `New-`, `Resolve-`
- **No inline comments** unless a section is genuinely non-obvious (e.g., a workaround for a known API quirk)
- **Output shape** — always `PSCustomObject` via `New-METCheckResult`, never raw strings
- **Error handling** — `try/catch` on all EXO/Graph/Teams calls; non-terminating errors surfaced in the `Error` field of the result object, not thrown. Populate it via `New-METCheckResult`'s `-ErrorMessage` parameter, never `-Error` — `$Error` is a PowerShell automatic variable and using it as a param name trips `PSAvoidAssignmentToAutomaticVariable`.
- **No `Write-Host` in checks or library code** — use `Write-Verbose` for progress, `Write-Warning` for non-fatal issues. `Get-METReport` and `Test-METPrerequisites` are the sole exceptions (coloured console display output); `PSAvoidUsingWriteHost` is disabled repo-wide in `PSScriptAnalyzerSettings.psd1` for that reason.
- **Secure by default** — no credential params, no plain-text secrets; all auth via `Connect-METSession` using modern auth / service principal / managed identity
- **Param blocks** — all public functions use `[CmdletBinding()]` and typed parameters
- **No positional parameters** on public functions
- Check scripts are standalone `.ps1` files, not functions — see [Check Execution Model](#check-execution-model) below.

---

## Check Result Schema

Every check returns one or more objects from `New-METCheckResult`. Shape:

```powershell
[PSCustomObject]@{
    CheckId          = 'MET-MDO001'           # String — matches filename prefix
    Category         = 'MDO'                   # MDO | EXO | Teams
    Name             = 'Safe Links Policy'     # Human-readable name
    Result           = 'Fail'                  # Pass | Fail | Warning | Info | NotApplicable
    Severity         = 'High'                  # Critical | High | Medium | Low | Informational
    Score            = 0                       # Int 0-100 contribution to posture index
    AffectedObject   = 'Default Policy'        # What was assessed
    Finding          = 'Safe Links is disabled for email' # What was found
    Recommendation   = 'Enable Safe Links...'  # Actionable fix
    ReferenceUrl     = 'https://aka.ms/...'    # Microsoft docs link
    Timestamp        = [datetime]::UtcNow
    Error            = $null                   # Populated if the check itself failed to run
}
```

---

## Invoke-METTriage — Behaviour

```powershell
# Run all checks
Invoke-METTriage

# Run only MDO checks
Invoke-METTriage -Category MDO

# Run specific check IDs
Invoke-METTriage -CheckId MET-MDO001, MET-EXO001

# Run against a delegated org (MSSP scenario)
Invoke-METTriage -DelegatedOrganization contoso.onmicrosoft.com

# Exclude checks
Invoke-METTriage -ExcludeCheckId MET-EXO007

# Dry-run: list what would run without connecting or executing anything
Invoke-METTriage -ListChecks

# Stream results as each check completes, instead of buffering
Invoke-METTriage -PassThru

# Full per-object detail (skip the multi-item aggregation described below)
Invoke-METTriage -Detailed
```

Returns `[PSCustomObject[]]` — the full collection of check results. `Get-METReport` handles formatting.

> `-DelegatedOrganization` is declared on the param block but not yet wired into the check-execution path — it's a placeholder for future MSSP support (hence its exclusion from `PSReviewUnusedParameter` in `PSScriptAnalyzerSettings.psd1`). Don't assume it changes behavior today.

### Check Execution Model

`Invoke-METTriage` does not dot-source `Checks/` at module load time (unlike `Public/` and `Private/`, which `MET.psm1` loads on import). Instead, each call to `Invoke-METTriage`:

1. Discovers check scripts fresh via `Get-ChildItem -Path Checks -Recurse -Filter 'MET-*.ps1'` — dropping a new file into `Checks/<Category>/` is enough to register it; no manifest or export list to update.
2. Pre-fetches shared context once (currently `AcceptedDomains` via `Get-AcceptedDomain`) into a `$METContext` hashtable, so every check that needs it doesn't repeat the same round-trip.
3. Runs each check inside a wrapper scriptblock — `& { param($METContext) . $checkPath } $METContext` — rather than a plain `. $checkPath`. This does three things simultaneously: injects `$METContext` as a local variable the check script can read; scopes `return` inside the check to the scriptblock instead of exiting `Invoke-METTriage` itself; and because hashtables are reference types, lets a check mutate `$METContext` (e.g. cache group membership) so later checks reuse the work.
4. Catches any terminating error per-check and converts it into a synthetic `Fail`/`High` result with the exception text in `Error`, so one broken check never aborts the run.
5. Unless `-Detailed` or `-PassThru` is passed, aggregates multiple result objects sharing the same `CheckId` (e.g. one per domain or per policy) into a single summary object — see `Get-METAggregationNoun` in `Invoke-METTriage.ps1` for the per-check-family noun used in that summary (`domains`, `quarantine policies`, default `policies`).

---

## Get-METReport — Behaviour

```powershell
# Console summary (default)
$results | Get-METReport

# JSON export
$results | Get-METReport -Format JSON -OutputPath ./MET-report.json

# HTML report (auto-opens in default browser)
$results | Get-METReport -Format HTML -OutputPath ./MET-report.html

# All formats at once
$results | Get-METReport -Format All -OutputPath ./assessments/contoso-2026-06-01/
```

Console output must include:
- Overall posture score (0–100, weighted average)
- Per-category breakdown (MDO / EXO / Teams)
- Fail/Warning items in a table (CheckId, Severity, AffectedObject, Finding)
- Pass count summary

---

## HTML Report Specification

The HTML report is a **single self-contained file** — all CSS and JS inlined, no CDN dependencies, works offline. It auto-opens in the default browser after generation. Inspired by microsoft/adoqr's report UX.

### Layout

```
┌─────────────────────────────────────────────────────────────┐
│  MET — Security Posture Scanner for MDO, EXO and Teams                │
│  Tenant: contoso.onmicrosoft.com   Run: 2026-06-01 14:32 UTC│
├─────────────────────────────────────────────────────────────┤
│  [Score: 74 / Fair]  MDO: 81  EXO: 68  Teams: 72           │
│  ● 18 Pass  ● 5 Fail  ● 3 Warning  ● 1 Not Applicable      │
├─────────────────────────────────────────────────────────────┤
│  [All] [MDO] [EXO] [Teams] [Accepted]    🔍 Search...  ▼    │
├─────────────────────────────────────────────────────────────┤
│  Check cards ...                                            │
└─────────────────────────────────────────────────────────────┘
```

### Header / Score Banner

- Tenant name and run timestamp (UTC)
- Posture score as a large number with band label (Critical / Poor / Fair / Good / Excellent)
- Three category sub-scores (MDO / EXO / Teams) as smaller badges
- Count summary: Pass / Fail / Warning / NotApplicable / Error

### Tabs

| Tab | Content |
|---|---|
| All | All checks regardless of result |
| MDO | Only `Category = 'MDO'` checks |
| EXO | Only `Category = 'EXO'` checks |
| Teams | Only `Category = 'Teams'` checks |
| Accepted | Checks where risk has been accepted (stored in `localStorage`) |

Tab counts update in real-time as filters are applied.

### Search and Filter Bar

- Free-text search box — filters cards live on `CheckId`, `Name`, `AffectedObject`, `Finding` (case-insensitive, no submit button)
- Severity filter dropdown: All / Critical / High / Medium / Low / Informational
- Result filter dropdown: All / Fail / Warning / Pass / NotApplicable
- Filters and search combine (AND logic)
- Result count shown: "Showing 7 of 27 checks"

### Check Cards

Each check result renders as a card:

```
┌─ [HIGH] MET-MDO001 · Safe Links ──────────────── [FAIL] ─┐
│  Affected: Default Safe Links Policy                        │
│  Finding:  Safe Links is disabled for email                 │
│  ▼ How to fix                                               │
│    1. Navigate to security.microsoft.com > Policies >...   │
│    2. ...                                                   │
│    📖 Microsoft Docs   ✓ Accept Risk                        │
└─────────────────────────────────────────────────────────────┘
```

- Card border color = Severity (red=Critical, orange=High, yellow=Medium, blue=Low, grey=Info)
- Result badge = Pass (green) / Fail (red) / Warning (amber) / N/A (grey)
- "How to fix" section is collapsed by default, expands on click — contains the `Recommendation` field rendered as numbered steps if line-breaks are present
- "Microsoft Docs" links to `ReferenceUrl`
- Pass cards render collapsed by default (title bar only) to reduce noise; expandable
- Error cards (check failed to run) shown with a distinct style and the `Error` field content

### Accept Risk Flow

- "Accept Risk" button on any Fail or Warning card
- Clicking opens an inline prompt for a business justification (free text, required)
- On confirm: card moves to the **Accepted** tab, badge changes to "Accepted", justification and acceptance date stored in `localStorage` keyed by `CheckId + TenantId`
- "Undo acceptance" button in the Accepted tab moves the card back
- Accepted controls are excluded from the posture score calculation displayed in the header
- Score banner updates live when acceptance state changes

### Top 5 Remediation Actions

Displayed as a prominent section above the check cards (collapsed by default on the All tab, expanded on first load):

- Ranked by: Severity weight × number of Fail results sharing the same remediation category
- Each entry shows: Rank, CheckId, Name, Severity, one-line Finding
- Clicking an entry scrolls to and expands the corresponding check card

### Styling

- Dark/light mode — respects `prefers-color-scheme`
- Microsoft Fluent-adjacent aesthetic: clean sans-serif, subtle card shadows, category colour coding consistent with MDO portal (blue for MDO, teal for EXO, purple for Teams)
- Responsive — usable at 1024px minimum width; not mobile-optimised
- No frameworks (no Bootstrap, no Tailwind) — plain CSS with CSS variables for theming

### JSON Output Schema

When `-Format JSON` or `-Format All`:

```json
{
  "tenant": "contoso.onmicrosoft.com",
  "runTimestamp": "2026-06-01T14:32:00Z",
  "METVersion": "0.1.0",
  "postureScore": 74,
  "categoryScores": { "MDO": 81, "EXO": 68, "Teams": 72 },
  "summary": { "Pass": 18, "Fail": 5, "Warning": 3, "NotApplicable": 1, "Error": 0 },
  "checks": [
    {
      "checkId": "MET-MDO001",
      "category": "MDO",
      "name": "Safe Links Policy",
      "result": "Fail",
      "severity": "High",
      "score": 0,
      "affectedObject": "Default Safe Links Policy",
      "finding": "Safe Links is disabled for email",
      "recommendation": "Enable Safe Links...",
      "referenceUrl": "https://aka.ms/...",
      "timestamp": "2026-06-01T14:32:05Z",
      "error": null
    }
  ]
}
```

Schema documented at `docs/schema/MET-report-schema.json` (JSON Schema draft-07).

---

## Connect-METSession — Behaviour

Wraps `Connect-ExchangeOnline`, `Connect-MicrosoftTeams`, and `Connect-MgGraph`. Detects existing sessions and skips reconnect. Supports:

- Interactive (device code / browser)
- Service principal with certificate (`-CertificateThumbprint`, `-AppId`, `-TenantId`)
- Managed Identity (`-ManagedIdentity`)
- Delegated org (`-DelegatedOrganization`) — for Connect-METSession only, unlike Invoke-METTriage's placeholder param of the same name
- `-SkipExchangeOnline`, `-SkipGraph`, `-SkipTeams` — opt out of a leg entirely (e.g. skip Graph if you're only running EXO checks)

---

## Check Inventory Detail

### MDO Checks

| ID | Name | What it checks |
|---|---|---|
| MET-MDO001 | Safe Links | Enabled for email and Office apps; `TrackClicks`, `EnableForInternalSenders`, real-time scan |
| MET-MDO002 | Safe Attachments | Enabled; action is `Block` or `DynamicDelivery`; not `Allow` |
| MET-MDO003 | Anti-Phish | Impersonation protection, mailbox intelligence, first-contact safety tip, action on impersonation detection |
| MET-MDO004 | Anti-Spoofing | `AuthenticationFailAction`, DMARC honor settings, unauthenticated sender indicators |
| MET-MDO005 | Anti-Malware | `ZapEnabled`, `EnableFileFilter`, admin notification, common attachment filter |
| MET-MDO006 | Anti-Spam Inbound | SCL thresholds, bulk complaint level, high-confidence spam action, phish action |
| MET-MDO007 | Anti-Spam Outbound | Forwarding rules, sending limits, auto-forward disabled per policy |
| MET-MDO008 | Preset Policy Coverage | Which users/groups are covered by Standard or Strict preset; uncovered recipient gap |
| MET-MDO009 | ZAP | ZAP enabled for spam and phish in all active policies |
| MET-MDO010 | Priority Accounts | Priority account tag applied; differentiated protection policy active |
| MET-MDO011 | User Tags | Tags in use; alert policies referencing tags exist |
| MET-MDO012 | Safe Documents | `EnableSafeDocs` enabled; `AllowSafeDocsOpen` disabled (via `Get-AtpPolicyForO365`) |

### EXO Checks

| ID | Name | What it checks |
|---|---|---|
| MET-EXO001 | DMARC | DMARC record present; policy is `quarantine` or `reject` (not `none`); `rua` reporting configured |
| MET-EXO002 | DKIM | DKIM signing enabled for all accepted domains; key length ≥ 2048 |
| MET-EXO003 | SPF | SPF record present; not `+all`; within 10-lookup limit |
| MET-EXO004 | Quarantine Policies | Default quarantine policies reviewed; user notification enabled; no `AdminOnlyAccessPolicy` on high-confidence phish |
| MET-EXO005 | Tenant Allow/Block List | Stale allow entries (>90 days); overly broad wildcard allows; allow count vs block ratio |
| MET-EXO006 | User Reported Message Settings | Report button mode (built-in Microsoft vs. non-Microsoft add-in via `EnableThirdPartyAddress`); `EnableReportToMicrosoft`; SecOps mailbox routing for all three flows (Junk / Not Junk / Phishing via `ReportJunkToCustomizedAddress` etc.); user post-review notifications |
| MET-EXO007 | Transport Rule Audit | Rules that bypass spam filtering (`SCLJunk=-1`) or disable safe links; informational listing |
| MET-EXO008 | Quarantine Retention | `QuarantineRetentionPeriod` ≥ 30 days in all anti-spam policies (default is 15; Standard/Strict recommend 30) |
| MET-EXO009 | Quarantine Policy Verdict Alignment | Cross-references every filter policy (anti-spam, anti-malware, anti-phish, Safe Attachments) with its assigned quarantine tag; verifies `PermissionToRelease = $false` for high-risk verdicts (Malware, High-Confidence Phish, impersonation) and warns for medium-risk (Phish, Spoof, Mailbox Intelligence) — catches custom quarantine policies that are too permissive for the verdict they protect |

### Teams Checks

| ID | Name | What it checks |
|---|---|---|
| MET-Teams001 | Safe Links for Teams | `EnableSafeLinksForTeams` enabled in Safe Links policies covering Teams users |
| MET-Teams002 | Safe Attachments for Teams | Global `EnableATPForSPOTeamsODB` enabled; `EnableSafeAttachmentsForTeams` enabled in at least one policy |
| MET-Teams003 | Meeting Protection | External access settings; anonymous join policy; lobby bypass settings from a security perspective |
| MET-Teams004 | ZAP for Teams | `TeamsProtectionPolicy.ZapEnabled`; malware and high-confidence phish quarantine tags set to `AdminOnlyAccessPolicy` |
| MET-Teams005 | Teams User Reporting | `ReportTeamsMsgEnabled` in report submission policy; `AllowSecurityEndUserReporting` in Teams messaging policy |

---

## Scoring Model

- Each check has a `Severity` weight: Critical=40, High=20, Medium=10, Low=5, Informational=0
- `Score` per check result: 100 if Pass, 0 if Fail, 50 if Warning
- Overall posture index = weighted average across all applicable checks
- Displayed as 0–100 with a band label: 0–39 Critical, 40–59 Poor, 60–79 Fair, 80–94 Good, 95–100 Excellent

---

## Current State (v0.5.0)

All 26 checks are implemented across MDO (12), EXO (9), and Teams (5), plus `Test-METPrerequisites` for pre-flight dependency checks. Console, JSON, and HTML report formats are all shipped. See `ROADMAP.md` for the full version history and `PrivateData.PSData.ReleaseNotes` in `MET.psd1` for the latest release's changes.

Backlog (not yet started):
- SARIF output for GitHub Code Scanning integration
- Azure Automation / GitHub Actions wrapper examples
- Signed module release for PSGallery publication

---

## Publishing

- **PSGallery**: publish on git tag `v*` via `publish.yml`
- **Module name**: `MET`
- **Tags**: `MDO`, `Microsoft365`, `Defender`, `ExchangeOnline`, `Teams`, `Security`, `Posture`, `Assessment`
- **ProjectUri**: `https://github.com/pthoor/MET`
- **LicenseUri**: MIT

---

## Non-Goals

- No GUI
- No agent or scheduled runner (out of scope — consumers can wrap in Azure Automation / GitHub Actions themselves)
- No remediation / auto-fix — assessment only
- No Terraform, ARM, or Python
- No dependency on the legacy `MSOnline` or `AzureAD` modules
