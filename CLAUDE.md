# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# MET - Security Posture Scanner for MDO, EXO and Teams

> Open-source PowerShell module for assessing Microsoft Defender for Office 365 (MDO), Exchange Online (EOP), and Microsoft Teams protection posture.

---

## Mission

MET assesses the security posture of an M365 tenant across MDO, EXO/EOP, and Teams threat protection. It produces structured, machine-readable output (PSCustomObject / JSON) suitable for human review, CI/CD gates, SIEM ingestion, and dashboards. It is not a replacement for the built-in MDO Configuration Analyzer - it goes further: Teams protection, email authentication, quarantine policy hygiene, per-user coverage gaps, and Tenant Allow/Block List hygiene.

Comparable tools for context:
- **ORCA** (cammurray/orca) - MDO/EOP HTML report, no Teams, no structured output, showing its age
- **MDOThreatPolicyChecker** (microsoft/CSS-Exchange) - per-user policy resolution only, not a posture assessment

---

## Repository Layout

```
MET/
├── MET.psd1                         # Module manifest
├── MET.psm1                         # Module root - dot-sources Public/ and Private/
├── Public/
│   ├── Invoke-METTriage.ps1         # Main entry point - runs all or selected checks
│   ├── Get-METReport.ps1            # Formats and exports results (console / JSON / HTML)
│   ├── Connect-METSession.ps1       # Handles EXO + Teams + Graph auth
│   ├── Disconnect-METSession.ps1    # Tears down all three legs; clears tenant-identity tracking
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
│   ├── Find-METRuleContradictions.ps1 # Detects conflicting transport rule conditions
│   ├── Get-METPresetSecurityPolicyTier.ps1 # Returns 'Strict'/'Standard'/$null for a filter/quarantine policy name
│   ├── Test-METIsPresetSecurityPolicyName.ps1 # Bool wrapper over Get-METPresetSecurityPolicyTier - is this policy name preset-generated?
│   ├── Test-METIsBuiltInQuarantinePolicyName.ps1 # Is this one of the 4 immutable built-in quarantine policies (not admin-editable)?
│   ├── Get-METCertificateFromFile.ps1 # Loads an X509Certificate2 from a PFX file + SecureString password, for Graph/Teams cert-based auth on non-Windows
│   └── Resolve-METTenantGuid.ps1    # Resolves a domain name or GUID to the tenant's GUID via unauthenticated OIDC discovery, for tenant-mismatch checks in Connect-METSession
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
│   │   ├── MET-MDO012-SafeDocuments.ps1
│   │   └── MET-MDO013-PolicyPrecedenceConflicts.ps1
│   ├── EXO/
│   │   ├── MET-EXO001-DMARC.ps1
│   │   ├── MET-EXO002-DKIM.ps1
│   │   ├── MET-EXO003-SPF.ps1
│   │   ├── MET-EXO004-QuarantinePolicy.ps1
│   │   ├── MET-EXO005-TenantAllowBlockList.ps1
│   │   ├── MET-EXO006-SubmissionPolicy.ps1
│   │   ├── MET-EXO007-TransportRuleAudit.ps1
│   │   ├── MET-EXO008-QuarantineRetention.ps1
│   │   ├── MET-EXO009-QuarantinePolicyVerdictAlignment.ps1
│   │   ├── MET-EXO010-DirectSend.ps1
│   │   ├── MET-EXO011-ConnectorHygiene.ps1
│   │   ├── MET-EXO012-MailboxForwarding.ps1
│   │   ├── MET-EXO013-SpoofIntelligenceAllowList.ps1
│   │   ├── MET-EXO014-AdvancedDeliveryPolicy.ps1
│   │   ├── MET-EXO015-ExternalSenderTag.ps1
│   │   ├── MET-EXO016-ArcTrustedSealers.ps1
│   │   ├── MET-EXO017-QuarantineNotificationCadence.ps1
│   │   ├── MET-EXO018-RemoteDomainForwarding.ps1
│   │   ├── MET-EXO019-SmtpAuthentication.ps1
│   │   ├── MET-EXO020-ConnectionFilterPolicy.ps1
│   │   ├── MET-EXO021-MailboxAuditing.ps1
│   │   ├── MET-EXO022-SharingPolicy.ps1
│   │   └── MET-EXO023-UnifiedAuditLog.ps1
│   └── Teams/
│       ├── MET-Teams001-SafeLinks.ps1
│       ├── MET-Teams002-SafeAttachments.ps1
│       ├── MET-Teams003-MeetingProtection.ps1
│       ├── MET-Teams004-ZAPForTeams.ps1
│       ├── MET-Teams005-TeamsUserReporting.ps1
│       ├── MET-Teams006-ExternalAccess.ps1
│       ├── MET-Teams007-GuestConfiguration.ps1
│       ├── MET-Teams008-AppPermissionPolicy.ps1
│       ├── MET-Teams009-TrialTenantFederation.ps1
│       ├── MET-Teams010-ExternalAccessPolicyDrift.ps1
│       ├── MET-Teams011-SecOpsBlocklistAuthority.ps1
│       ├── MET-Teams012-CallReporting.ps1
│       ├── MET-Teams014-CrossTenantAccess.ps1
│       └── MET-Teams015-EmailIntegration.ps1
├── Tests/
│   ├── Unit/
│   │   ├── New-METCheckResult.Tests.ps1
│   │   ├── Resolve-METCoverageMatrix.Tests.ps1
│   │   ├── Checks.MDO.Tests.ps1          # MDO001-MDO012 (MDO013 has its own file below)
│   │   ├── Checks.EXO.Tests.ps1          # EXO001-EXO009 (EXO010+ each have their own file below)
│   │   ├── Checks.Teams.Tests.ps1        # Teams001-Teams005 (Teams006+ each have their own file below)
│   │   └── Checks.<ID>.Tests.ps1         # One self-contained file per check from MDO013/EXO010+/Teams006+ onward - each check's tests now get a dedicated file (own BeforeAll, own cmdlet stubs) rather than sharing one per-category file. Avoids every new check needing to touch a shared file.
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
| ExchangeOnlineManagement | 3.9+ (modern auth, REST-based) - required |
| Microsoft.Graph.Identity.SignIns / .Groups | 2.x - optional; a missing module or failed Graph connection is non-fatal, and group expansion degrades to Exchange Online cmdlets (see [Connection Requirements for New Checks](#connection-requirements-for-new-checks)) |
| MicrosoftTeams | 6.x+ (latest 7.x) - optional; Teams checks skip gracefully if absent |
| Pester | 5.x for all tests |

No Python. No ARM. No Terraform. No legacy Basic Auth. Full support is Windows-only - on Linux/macOS every check runs except EXO001 (DMARC) and EXO003 (SPF), which need `Resolve-DnsName`; `Resolve-METDnsName` falls back to `dig`/`nslookup` there. Teams auth on Linux/macOS additionally needs `-UseDeviceAuthentication`: MicrosoftTeams 7.9.0+ defaults to WAM, which P/Invokes `kernel32.dll`. `Connect-METSession` passes `-DisableWAM` automatically off Windows.

`RequiredModules` is deliberately empty in `MET.psd1` - declaring them there causes a hard import failure when a dependency is missing, which would prevent `Test-METPrerequisites` from running and guiding the user. Dependencies are checked at runtime instead.

---

## Development Commands

```powershell
# Import the module locally (no build step - this is a pure PowerShell script module)
Import-Module ./MET.psd1 -Force

# Lint (matches CI's lint job exactly - must be zero errors)
Install-Module PSScriptAnalyzer -MinimumVersion 1.21.0 -Scope CurrentUser
Invoke-ScriptAnalyzer -Path Public,Private,Checks -Recurse -Settings ./PSScriptAnalyzerSettings.psd1

# Unit tests (no tenant connection required - all EXO/Graph/Teams cmdlets are mocked)
$config = New-PesterConfiguration
$config.Run.Path = './Tests/Unit'
$config.Output.Verbosity = 'Detailed'
Invoke-Pester -Configuration $config

# Run a single test file
Invoke-Pester -Path ./Tests/Unit/Checks.MDO.Tests.ps1 -Output Detailed

# Run a single test by name
Invoke-Pester -Path ./Tests/Unit -FullNameFilter '*MET-EXO001*' -Output Detailed

# Integration tests (also mocked - no live tenant required)
Invoke-Pester -Path ./Tests/Integration -Output Detailed
```

CI (`pester.yml`) runs three jobs in order: `lint` (PSScriptAnalyzer, zero errors required) → `test` (unit tests with a 30% JaCoCo coverage gate, then integration tests) → `credential-scan` (TruffleHog). Lint failures block the test job.

---

## Coding Conventions

- **Approved verbs only** - `Invoke-`, `Get-`, `Test-`, `Connect-`, `New-`, `Resolve-`
- **No inline comments** unless a section is genuinely non-obvious (e.g., a workaround for a known API quirk)
- **Output shape** - always `PSCustomObject` via `New-METCheckResult`, never raw strings
- **Error handling** - `try/catch` on all EXO/Graph/Teams calls; non-terminating errors surfaced in the `Error` field of the result object, not thrown. Populate it via `New-METCheckResult`'s `-ErrorMessage` parameter, never `-Error` - `$Error` is a PowerShell automatic variable and using it as a param name trips `PSAvoidAssignmentToAutomaticVariable`.
- **No `Write-Host` in checks or library code** - use `Write-Verbose` for progress, `Write-Warning` for non-fatal issues. `Get-METReport` and `Test-METPrerequisites` are the sole exceptions (coloured console display output); `PSAvoidUsingWriteHost` is disabled repo-wide in `PSScriptAnalyzerSettings.psd1` for that reason.
- **Secure by default** - no credential params, no plain-text secrets; all auth via `Connect-METSession` using modern auth / service principal / managed identity
- **Param blocks** - all public functions use `[CmdletBinding()]` and typed parameters
- **No positional parameters** on public functions
- Check scripts are standalone `.ps1` files, not functions - see [Check Execution Model](#check-execution-model) below.

---

## Check Result Schema

Every check returns one or more objects from `New-METCheckResult`. Shape:

```powershell
[PSCustomObject]@{
    CheckId          = 'MET-MDO001'           # String - matches filename prefix
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

## Invoke-METTriage - Behaviour

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

Returns `[PSCustomObject[]]` - the full collection of check results. `Get-METReport` handles formatting.

> `-DelegatedOrganization` is declared on the param block but not yet wired into the check-execution path - it's a placeholder for future MSSP support (hence its exclusion from `PSReviewUnusedParameter` in `PSScriptAnalyzerSettings.psd1`). Don't assume it changes behavior today.

### Check Execution Model

`Invoke-METTriage` does not dot-source `Checks/` at module load time (unlike `Public/` and `Private/`, which `MET.psm1` loads on import). Instead, each call to `Invoke-METTriage`:

1. Discovers check scripts fresh via `Get-ChildItem -Path Checks -Recurse -Filter 'MET-*.ps1'` - dropping a new file into `Checks/<Category>/` is enough to register it; no manifest or export list to update.
2. Pre-fetches shared context once (currently `AcceptedDomains` via `Get-AcceptedDomain`) into a `$METContext` hashtable, so every check that needs it doesn't repeat the same round-trip.
3. Runs each check inside a wrapper scriptblock - `& { param($METContext) . $checkPath } $METContext` - rather than a plain `. $checkPath`. This does three things simultaneously: injects `$METContext` as a local variable the check script can read; scopes `return` inside the check to the scriptblock instead of exiting `Invoke-METTriage` itself; and because hashtables are reference types, lets a check mutate `$METContext` (e.g. cache group membership) so later checks reuse the work.
4. Catches any terminating error per-check and converts it into a synthetic `Fail`/`High` result with the exception text in `Error`, so one broken check never aborts the run.
5. Unless `-Detailed` or `-PassThru` is passed, aggregates multiple result objects sharing the same `CheckId` (e.g. one per domain or per policy) into a single summary object - see `Get-METAggregationNoun` in `Invoke-METTriage.ps1` for the per-check-family noun used in that summary (`domains`, `quarantine policies`, default `policies`).

---

## Get-METReport - Behaviour

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

The HTML report is a **single self-contained file** - all CSS and JS inlined, no CDN dependencies, works offline. It auto-opens in the default browser after generation. Inspired by microsoft/adoqr's report UX.

### Layout

```
┌─────────────────────────────────────────────────────────────┐
│  MET - Security Posture Scanner for MDO, EXO and Teams                │
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

- Free-text search box - filters cards live on `CheckId`, `Name`, `AffectedObject`, `Finding` (case-insensitive, no submit button)
- Severity filter dropdown: All / Critical / High / Medium / Low / Informational
- Result filter dropdown: All / Fail / Warning / Pass / NotApplicable / Info / Error - Error is its own bucket (a check whose `Error` field is populated), mutually exclusive with the Result-based options even though the check still carries a Result value underneath
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
- "How to fix" section is collapsed by default, expands on click - contains the `Recommendation` field rendered as numbered steps if line-breaks are present
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

- Dark/light mode - respects `prefers-color-scheme`
- Microsoft Fluent-adjacent aesthetic: clean sans-serif, subtle card shadows, category colour coding consistent with MDO portal (blue for MDO, teal for EXO, purple for Teams)
- Responsive - usable at 1024px minimum width; not mobile-optimised
- No frameworks (no Bootstrap, no Tailwind) - plain CSS with CSS variables for theming

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

## Connect-METSession - Behaviour

Wraps `Connect-ExchangeOnline`, `Connect-MicrosoftTeams`, and `Connect-MgGraph`. Detects existing sessions and skips reconnect - but only after verifying the existing session actually belongs to the requested tenant/org and auth mode; a mismatch throws (naming the actually-connected org) rather than silently proceeding against the wrong tenant. Supports:

- Interactive (browser by default; `-UseDeviceAuthentication` as a documented headless-only fallback - see below)
- Service principal with certificate: `-CertificateThumbprint` (Windows certificate store) or `-CertificatePath` + `-CertificatePassword` (any platform, including Linux/macOS/Codespaces - `-CertificateThumbprint` is Windows-only per Microsoft's own docs), plus `-AppId`, `-TenantId`
- Managed Identity (`-ManagedIdentity`)
- Delegated org (`-DelegatedOrganization`) - for Connect-METSession only, unlike Invoke-METTriage's placeholder param of the same name. Threaded through to all three legs (EXO natively; Graph and Teams via their own `-TenantId` parameter, both of which accept a domain string for exactly this CSP/GDAP scenario - previously silently ignored for Graph/Teams, so a delegated-org run could authenticate against the operator's own home tenant instead of the customer's)
- `-SkipExchangeOnline`, `-SkipGraph`, `-SkipTeams` - opt out of a leg entirely (e.g. skip Graph if you're only running EXO checks)
- `Disconnect-METSession` - tears down all three legs (each in its own try/catch), and clears the tenant-identity tracking used for the reuse check above. Run this before switching `-DelegatedOrganization` in the same PowerShell session.

Device-code auth (`-UseDeviceAuthentication`) is a documented phishing vector (Storm-2372 and follow-on campaigns; Microsoft's own guidance is "block wherever possible, allow only where necessary") - `Connect-METSession` emits a `Write-Warning` whenever it's used, and none of the connection-failure retry messages suggest it as a first-line fix anymore; it's scoped to the genuinely headless case (no browser reachable at all).

`Get-METReport`'s header (console/JSON/HTML) surfaces which auth mode/tenant/services were used for the run, read from module-scoped state `Connect-METSession` sets on success - lets a customer's SOC reconcile a sign-in they see in their own logs with a known MET run instead of triaging it as an incident.

### Connection Requirements for New Checks

Every MDO/EXO check needs Exchange Online - it is always connected (hard requirement; `Connect-METSession` aborts if it fails). Teams-category checks are split: `MET-Teams001/002/004` actually call Exchange-hosted cmdlets (`Get-SafeLinksPolicy`, `Get-TeamsProtectionPolicy`), while `MET-Teams003/005/006/007/008` need the native `MicrosoftTeams` module (`Get-Cs*`) - both are proven to coexist safely with Exchange Online in one process.

Microsoft Graph is different: its bundled MSAL build routinely conflicts with ExchangeOnlineManagement's in the same PowerShell process (a `Microsoft.Identity.Client`/`Microsoft.IdentityModel.Abstractions` version mismatch that has no reliable fix across currently-published module versions - not an environment or OS issue, just release-cadence drift between Microsoft's own PowerShell modules). This has been checked exhaustively, not just observed once: every published `ExchangeOnlineManagement` version from 3.7.0 through 3.10.1 was inspected for its bundled `Microsoft.Identity.Client` version, and the value jumps directly from `4.74.1.0` (3.9.0-3.9.2) to `4.83.1.0` (3.10.0-3.10.1) - skipping the `4.82.x` range entirely, which is exactly what `Microsoft.Graph.Authentication` 2.39.0 (`4.82.1.0`) and `MicrosoftTeams` 7.9.0 (`4.82.0.0`) both need. EXO 3.9.2's older `4.74.1.0` also fails outright against Teams 7.9.0 (`FileLoadException`, HRESULT `0x80131040`). So there is no version triple of EXO+Graph+Teams that coexists in one process today, and pinning any of them is a net loss versus the current design - see ROADMAP.md "Under Investigation" for the full evidence and the proposed subprocess-isolation fix. `Connect-METSession` treats a Graph connection failure as non-fatal and continues without it, exactly like it already does for Teams. `Expand-METGroupMembership` is the only Graph call site in the codebase, and it degrades gracefully to Exchange Online cmdlets (`Get-DistributionGroupMember` for distribution/mail-enabled security groups, `Get-UnifiedGroupLinks` for Microsoft 365 Groups) when Graph is unavailable - which covers every group type EOP/MDO policies can actually target (dynamic-membership groups are not supported as policy recipient conditions at all, Graph or no Graph).

When adding a new check: default to Exchange Online or native Teams cmdlets. Only add a direct Graph dependency if there is genuinely no Exchange Online equivalent for the data you need (e.g. Conditional Access, Entra role assignments) - and if you do, it must degrade non-fatally like `Expand-METGroupMembership` does, not abort the run.

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
| MET-MDO013 | Policy Precedence Conflicts | Finds custom anti-spam, anti-malware, Anti-Phish, Safe Links, and Safe Attachments rules whose targeted recipients are also covered by a Standard/Strict preset; incomplete source data produces a failed check instead of a clean result |
| MET-MDO014 | Group Reference Audit | Every group referenced by an enabled EOP/MDO rule's `SentToMemberOf`; reports member count per group, flags 0-member groups as a silent-inert-policy condition |

### EXO Checks

| ID | Name | What it checks |
|---|---|---|
| MET-EXO001 | DMARC | DMARC record present; policy is `quarantine` or `reject` (not `none`); `rua` reporting configured |
| MET-EXO002 | DKIM | DKIM signing enabled for all accepted domains; key length ≥ 2048 |
| MET-EXO003 | SPF | SPF record present; not `+all`; within 10-lookup limit |
| MET-EXO004 | Quarantine Policies | Genuinely custom (non-built-in) quarantine policies only - flags `ESNEnabled = $false` combined with a granted end-user permission (a user given access to act on quarantined mail but never notified it exists). Excludes the 4 immutable built-ins (`AdminOnlyAccessPolicy`, `DefaultFullAccessPolicy`, `DefaultFullAccessWithNotificationPolicy`, `NotificationEnabledPolicy`) - a prior version flagged `AdminOnlyAccessPolicy`'s by-design "No access" as a misconfiguration on every tenant; fixed 2026-08-18 |
| MET-EXO005 | Tenant Allow/Block List | Stale allow entries (>90 days); overly broad wildcard allows; allow count vs block ratio |
| MET-EXO006 | User Reported Message Settings | Report button mode (built-in Microsoft vs. non-Microsoft add-in via `EnableThirdPartyAddress`); `EnableReportToMicrosoft`; SecOps mailbox routing for all three flows (Junk / Not Junk / Phishing via `ReportJunkToCustomizedAddress` etc.); user post-review notifications |
| MET-EXO007 | Transport Rule Audit | Rules that bypass spam filtering (`SCLJunk=-1`) or disable safe links; informational listing |
| MET-EXO008 | Quarantine Retention | `QuarantineRetentionPeriod` ≥ 30 days in default/custom anti-spam policies (default is 15). Preset (Standard/Strict) policies are recognized via `Test-METIsPresetSecurityPolicyName` and reported as fixed/non-configurable rather than given a `Set-*` recommendation that would error; also notes this same value governs anti-phish (spoof/impersonation) quarantine retention for the same recipient |
| MET-EXO009 | Quarantine Policy Verdict Alignment | Cross-references every filter policy (anti-spam, anti-malware, anti-phish, Safe Attachments) with its assigned quarantine tag; verifies `PermissionToRelease = $false` only for the two verdicts Microsoft's own Standard/Strict presets actually restrict this way (Malware, High-Confidence Phish) - impersonation/spoof/phish were removed from the restricted set 2026-08-18 after confirming Microsoft's own Strict preset uses Full-access policies for those, which the prior model incorrectly flagged as a Fail/Warning on every tenant using Strict or Standard. Preset-generated policy objects are skipped entirely via `Test-METIsPresetSecurityPolicyName` since their tags are guaranteed correct |
| MET-EXO017 | Quarantine Notification Cadence | `EndUserSpamNotificationFrequency` on the tenant-wide global quarantine policy (`DefaultGlobalTag`) - Info-only listing (4 hours / 1 day / 7 days); no Microsoft-recommended value exists |
| MET-EXO010 | Direct Send | `Get-OrganizationConfig` → `RejectDirectSend` - unauthenticated senders can otherwise relay mail through the tenant's own domain without SMTP auth, a path actively abused to spoof internal senders |
| MET-EXO011 | Mail Flow Connector Hygiene | `Get-InboundConnector` - flags enabled connectors with `RequireTls` off or no effective source IP/TLS certificate authentication binding; `SenderDomains` alone is not authentication |
| MET-EXO012 | Mailbox Forwarding | `Get-EXOMailbox` `ForwardingSmtpAddress`/`ForwardingAddress`/`DeliverToMailboxAndForward` - surfaces mailboxes with forwarding configured, flagging "silent" forwarding (no local copy) as the higher-risk BEC persistence pattern; inbox-rule-based forwarding is out of scope (does not scale to `Get-InboxRule` per mailbox) |
| MET-EXO013 | Spoof Intelligence Allow-List | `Get-TenantAllowBlockListSpoofItems -Action Allow` - reviews standing spoof-intelligence exceptions, distinguishing Internal vs. External spoof type |
| MET-EXO014 | Advanced Delivery Policy | `Get-ExoPhishSimOverrideRule` and `Get-ExoSecOpsOverrideRule` - surfaces enforceable phishing-simulation and SecOps mailbox override rules for periodic review (Info-only when retrieval succeeds) |
| MET-EXO015 | External Sender Warning Tag | `Get-ExternalInOutlook` - the native Outlook "External" banner, a user-facing (not filter-level) signal against lookalike-domain/BEC senders |
| MET-EXO016 | ARC Trusted Sealers | `Get-ArcConfig` → `ArcTrustedSealers` - Info-only listing of domains trusted to vouch for message authentication results via Authenticated Received Chain |
| MET-EXO018 | Remote Domain Automatic Forwarding | `Get-RemoteDomain` → `AutoForwardEnabled`, one result per remote domain. The tenant-wide `*` domain with auto-forward on is a Fail (automatic forwarding permitted to every external domain); a specific domain is a Warning. Third and independent forwarding control plane alongside MET-MDO007 (`AutoForwardingMode`) and MET-EXO012 (per-mailbox) - all three must be closed |
| MET-EXO019 | SMTP Client Authentication | `Get-TransportConfig` → `SmtpClientAuthenticationDisabled` tenant-wide; when that is already disabled, additionally enumerates per-mailbox re-enables via `Get-EXOCasMailbox` in its own try/catch, so an enumeration failure degrades to Warning-with-error-surfaced (not Pass - the override exposure went unverified) rather than aborting. Note the setting is protocol-level: SMTP AUTH supports OAuth as well as Basic, and Basic is blocked separately via `Set-AuthenticationPolicy -AllowBasicAuthSmtp $false`, so neither the check nor its docs claim an enabled tenant necessarily exposes a password-only endpoint |
| MET-EXO020 | Connection Filter Policy Hygiene | `Get-HostedConnectionFilterPolicy` → `IPAllowList` (Fail - allow-listed sources skip spam filtering *and* spoof intelligence), `EnableSafeList` (Warning - contents are not enumerable from PowerShell so they cannot be reviewed). Broad CIDR entries are called out separately; unparseable entries are skipped rather than guessed at |
| MET-EXO021 | Mailbox Audit Logging | `Get-OrganizationConfig` → `AuditDisabled`. Note the inverted sense: `$true` means auditing is OFF. An absent property is Pass-with-assumption, since Microsoft's platform default is on |
| MET-EXO022 | Calendar and Contact Sharing | `Get-SharingPolicy` → `Domains`, one result per policy. Warns on enabled policies sharing calendar *detail* or contacts with `*`/`Anonymous`; free/busy-simple to `*` passes explicitly. Disabled policies report Info, not Pass |
| MET-EXO023 | Unified Audit Log Ingestion | `Get-AdminAuditLogConfig` → `UnifiedAuditLogIngestionEnabled`. Unlike EXO021 an absent property is a Fail, not an assumed default - ingestion has shipped off in some tenants. Retention duration is explicitly **not** asserted (it needs a Purview connection this module does not open) and is documented as a manual follow-up |

### Teams Checks

| ID | Name | What it checks |
|---|---|---|
| MET-Teams001 | Safe Links for Teams | Effective-coverage model (like MET-MDO001): resolves the actual precedence-winning Safe Links policy per mailbox via `Resolve-METSafeLinksEffectivePolicy` (Strict preset > Standard preset > custom by priority > Built-In fallback) and flags recipients whose effective policy has `EnableSafeLinksForTeams` disabled - catches shadowing that a simple "does a Teams-enabled policy with an assigning rule exist" check cannot see |
| MET-Teams002 | Safe Attachments for Teams | Global `EnableATPForSPOTeamsODB` on `Get-AtpPolicyForO365` - the sole documented toggle for SPO/OneDrive/Teams protection. (Previously also required a nonexistent per-policy `EnableSafeAttachmentsForTeams` property on `Get-SafeAttachmentPolicy`, which doesn't exist on that cmdlet and caused false Fails on every tenant - removed 2026-08-18) |
| MET-Teams003 | Meeting Protection | External access settings; anonymous join policy; lobby bypass settings (`AllowPSTNUsersToBypassLobby`) from a security perspective, enumerated across all meeting policies (not just `Global`) |
| MET-Teams004 | ZAP for Teams | `TeamsProtectionPolicy.ZapEnabled`; malware and high-confidence phish quarantine tags set to `AdminOnlyAccessPolicy`; also flags `TeamsProtectionPolicyRule` exceptions that narrow effective ZAP coverage |
| MET-Teams005 | Teams User Reporting | `ReportChatMessageEnabled`/`ReportChatMessageToCustomizedAddressEnabled` in the report submission policy; `AllowSecurityEndUserReporting` in Teams messaging policy |
| MET-Teams006 | External Access / Federation Allow-List | `Get-CsTenantFederationConfiguration` - flags open federation (`AllowAllKnownDomains`), `AllowTeamsConsumer`/`AllowTeamsConsumerInbound`/`RestrictTeamsConsumerToExternalUserProfiles`, and an empty `BlockedDomains` deny-list; distinct control plane from Teams003's meeting-level anonymous join |
| MET-Teams007 | Guest Messaging/Calling Configuration | `Get-CsTeamsGuestMessagingConfiguration`/`Get-CsTeamsGuestCallingConfiguration` - flags guest-initiated 1:1 chat and private calling; distinct from federation (Teams006) and meeting join (Teams003) |
| MET-Teams008 | App Permission Policy Exposure | `Get-CsTeamsAppPermissionPolicy` (read-only) - flags any `*CatalogAppsType` not restricted to an explicit `AllowedAppList`/`BlockedAppList`, detected by exclusion since Microsoft requires policy changes via the admin center, not PowerShell `Set-`/`New-`. Recommendation notes the policy may be inert on tenants migrated to App Centric Management (ACM) - no cmdlet exists yet to detect migration state itself |
| MET-Teams009 | Trial Tenant Federation Exposure | `Get-CsTenantFederationConfiguration` → `ExternalAccessWithTrialTenants` (`Allowed`/`Blocked`) - disposable trial tenants are a low-effort first-contact vector distinct from Teams006's general federation allow-list |
| MET-Teams010 | Per-User External Access Policy Drift | `Get-CsExternalAccessPolicy`, enumerated across all non-`Global` instances - flags `EnableFederationAccess`/`EnablePublicCloudAccess` re-opening access for a specific user set under an otherwise-restrictive tenant-wide federation baseline |
| MET-Teams011 | SecOps Blocklist Authority & Blocked Entities | `SecurityTeamAllowBlockListDelegation` on `Get-CsTenantFederationConfiguration` (can SecOps block a malicious domain/user from the portal mid-incident) plus currently-blocked entities via `Get-CsTeamsExternalAccessConfiguration`; response-readiness, so `Disabled` is a Warning rather than a hard Fail |
| MET-Teams012 | Call Reporting (Vishing Surface) | `Get-CsTeamsCallingPolicy` → `ReportCall`, enumerated across all policies - closest native control to helpdesk-vishing (Storm-1811/3AM-style) attacks over a Teams call |
| MET-Teams014 | Cross-Tenant Guest & External Collaboration | Microsoft Graph `GET /policies/crossTenantAccessPolicy` + `/policies/authorizationPolicy` (`Policy.Read.All`, already in MET's default Graph scopes) - first check with a direct Graph dependency (not routed through `Expand-METGroupMembership`); degrades to `NotApplicable` non-fatally if Graph is unavailable |
| MET-Teams015 | Teams Email Integration | `Get-CsTeamsClientConfiguration` → `AllowEmailIntoChannel` - channel email addresses accept mail from outside the organisation and deliver it into the channel rather than a mailbox, so Exchange transport rules and mailbox-level policy never apply to it. Warning rather than Fail (it is a legitimate feature); an absent property is also a Warning rather than a silent pass |

---

## Scoring Model

- Each check has a `Severity` weight: Critical=40, High=20, Medium=10, Low=5, Informational=0
- `Score` per check result: 100 if Pass, 0 if Fail, 50 if Warning
- Overall posture index = weighted average across all applicable checks
- Displayed as 0–100 with a band label: 0–39 Critical, 40–59 Poor, 60–79 Fair, 80–94 Good, 95–100 Excellent

---

## Current State (v0.11.1)

All 51 checks are implemented across MDO (14), EXO (23), and Teams (14), plus `Test-METPrerequisites` for pre-flight dependency checks and `Disconnect-METSession` for session teardown. Console, JSON, and HTML report formats are all shipped. See `ROADMAP.md` for the full version history - v0.6.0 added 11 checks across the MDO/EOP mail-flow stack and Teams; v0.8.0 added 5 new Teams checks (009-012, 014) plus 5 enhancements to existing Teams checks (001, 003, 004, 006, 008); v0.9.0 fixed two confirmed quarantine-check false positives; v0.10.0 fixed a confirmed cross-customer data leak in session reuse (no tenant/org verification before reusing a live EXO/Graph/Teams connection), alongside certificate-file auth for non-Windows and a scoped-down, research-grounded device-code auth posture (Microsoft's own current guidance: "block wherever possible, allow only where necessary"). v0.11.0 added 7 checks (EXO018-EXO023, Teams015) closing gaps in control planes MET could previously see no state for - remote-domain auto-forwarding, legacy SMTP AUTH, connection-filter allow lists, mailbox and unified audit logging, calendar/contact sharing, and Teams channel email - plus 3 enhancements to existing checks (MDO003, MDO005, Teams003) and the first automated test coverage of the HTML report - which immediately caught a real defect: `ConvertTo-Json` collapsed the embedded check array for 0- and 1-result runs, killing the report's entire client script (blank page, no cards) and emitting `checks` as an object rather than an array in the JSON output. v0.11.1 fixed three HTML-report defects that made a check which failed to run effectively invisible: no ERROR badge on a card carrying a populated `Error` field, no Error option in the Result filter, and the risk-accepted badge taking precedence over the error state.

Backlog (not yet started):
- SARIF output for GitHub Code Scanning integration
- Azure Automation / GitHub Actions wrapper examples
- Signed module release for PSGallery publication
- Attack Simulation Training coverage, Secure Score correlation, risky Teams app/bot catalog enumeration, and ACM migration-state detection - see ROADMAP.md "Under Investigation" (each needs a new Graph scope/module dependency decision, or an as-yet-unconfirmed detection method, before becoming a committed check)
- AIR (Automated investigation and response) auto-remediation settings are documented as a manual review item in `README.md`, not a check - no supported PowerShell cmdlet or public Graph API exists to read or set them
- `DisallowInfectedFileDownload` (SPO/OneDrive/Teams infected-file download blocking) and the SPO/OneDrive/Teams malware-detected alert policy are also documented as manual review items in `README.md`, not checks - both have a real cmdlet (`Get-SPOTenant`, `Get-ProtectionAlert`), but the former needs a whole new `Microsoft.Online.SharePoint.PowerShell`/PnP dependency and the latter needs a second `Connect-IPPSSession` leg plus Purview permissions beyond Security Reader; neither was judged worth the added dependency/auth surface for what each buys

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
- No agent or scheduled runner (out of scope - consumers can wrap in Azure Automation / GitHub Actions themselves)
- No remediation / auto-fix - assessment only
- No Terraform, ARM, or Python
- No dependency on the legacy `MSOnline` or `AzureAD` modules

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- For codebase questions, first run `graphify query "<question>"` when graphify-out/graph.json exists. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
