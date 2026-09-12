# Audit Section D Documentation Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the residual Section D audit findings by aligning MET's public and contributor documentation with the behavior shipped on merged PR #32.

**Architecture:** Keep runtime code and tests untouched. Treat each check's `$METCheckInfo` and emitted `New-METCheckResult` branches as authoritative, move the remediation cookbook out of the product front door, and update independently owned document groups with a review gate after each task.

**Tech Stack:** Markdown, PowerShell 7.6, PSScriptAnalyzer 1.25.0, Pester 5.9.0, JSON Schema draft-07, Node.js/Playwright.

**Spec:** `docs/superpowers/specs/2026-09-11-audit-section-d-design.md`

## Global Constraints

- Base commit is `b52313f`; branch is `fix/audit-section-d-docs`.
- Runtime code, tests, workflows, `MET.psd1`, and `MET.psm1` must not change.
- Editable files are `README.md`, `CLAUDE.md`, `ROADMAP.md`, `docs/**`, plus the explicitly approved `Tests/Html/README.md` exception.
- Do not edit `SECURITY.md`; PR #30 already made the audited claim accurate and added npm Dependabot coverage.
- Do not add a `CONTROLS_META` maintenance step; PR #32 generates report descriptions from `$METCheckInfo.Description`.
- Preserve `error: null` in the JSON example because `New-METCheckResult` now emits null for an unset error and the schema permits null.
- The clean baseline is 1,276 passed unit tests with 2 skipped, and 24 passed integration tests.

---

### Task 1: Make README a truthful product front door

**Files:**
- Modify: `README.md`
- Create: `docs/baselines/promotions-folder.md`

**Interfaces:**
- Consumes: Current check metadata from `Checks/**/$METCheckInfo`, DNS behavior from `Private/Resolve-METDnsName.ps1`, and current output naming from `Public/Get-METReport.ps1`.
- Produces: A concise quick start, linked 51-check inventory, and an optional baseline document outside the core product narrative.

- [ ] **Step 1: Move the Promotions Folder cookbook without losing content**

Create `docs/baselines/promotions-folder.md` with a title and short scope warning, followed by the existing README content from `## Custom Policy Baseline - Promotions Folder` through `### MET checks that assess this baseline`. The warning must say that the commands mutate tenant configuration, are optional guidance, and are not executed by MET.

Replace the original 229-line README block with:

```markdown
## Optional remediation baseline

MET is assessment-only and never changes tenant configuration. The separate [Promotions Folder baseline](docs/baselines/promotions-folder.md) is optional deployment guidance for administrators who deliberately want that mail-flow design; its `New-*` and `Set-*` commands are not run by MET.
```

- [ ] **Step 2: Put the quick start before dependencies and permissions**

Add the CI and latest-release badges beneath the title, state that MET runs 51 checks, and place this compact flow before `## Dependencies`:

```powershell
Install-Module MET -Repository PSGallery -Scope CurrentUser
Test-METPrerequisites
Connect-METSession
$results = Invoke-METAssessment
$results | Get-METReport -Format HTML -OutputPath ./assessments
```

Remove the later duplicate install and six-step quickstart blocks. Keep discovery, service-principal, MSSP, scoped-run, and troubleshooting guidance under `## Usage`.

- [ ] **Step 3: Correct the high-impact README claims**

Make these exact semantic corrections:

- Platform: all 51 checks run on Windows, Linux, and macOS; EXO001/EXO003 use `Resolve-DnsName` on Windows, then `dig`, `nslookup`, and configurable DNS-over-HTTPS elsewhere. State that DoH discloses queried domains and can be disabled with `MET_DOH_RESOLVER=none`.
- Permissions: remove `Get-ProtectionAlert` and `Get-Tag` from the Security Reader row.
- MDO011: “Portal-review pointer for user tags and tag-aware alert policies; no programmatic assessment (always Info/Low).”
- Output folder: use `20260602-102530-contoso.onmicrosoft.com` and remove “now”.

- [ ] **Step 4: Link the inventory and align names with metadata**

Wrap every inventory ID with its existing `docs/checks/MET-<ID>-<slug>.md` link. Update the ten stale README names to:

```text
MET-MDO001  Safe Links Effective Coverage
MET-MDO003  Anti-Phishing Effective Coverage
MET-MDO005  Anti-Malware Effective Coverage
MET-MDO009  ZAP Effective Coverage
MET-EXO006  User Reported Message Settings
MET-EXO010  Direct Send Protection
MET-EXO016  ARC Trusted Sealers Review
MET-EXO022  Calendar and Contact Sharing Policies
MET-Teams008 App Permission Policy
MET-Teams014 Cross-Tenant Guest & External Collaboration Restrictions
```

- [ ] **Step 5: Surface the named operational options**

Add a compact table under Usage documenting:

```text
Connect-METSession -ManagedIdentity
Connect-METSession -SkipExchangeOnline
Invoke-METAssessment -ListChecks
Invoke-METAssessment -Detailed
Get-METReport -PassThru
```

Describe only current behavior established by each command's comment-based help.

- [ ] **Step 6: Validate README structure and links**

Run a PowerShell validation that extracts `docs/checks/*.md` targets from README, resolves each path, and fails unless all 51 inventory rows link to an existing page. Confirm the Promotions block appears only in the baseline document and that README places Quick start before Dependencies.

- [ ] **Step 7: Commit Task 1**

```bash
git add README.md docs/baselines/promotions-folder.md
git commit -m "docs: refocus README on assessment workflow"
```

---

### Task 2: Correct check-specific documentation

**Files:**
- Modify: `docs/checks/MET-MDO011-UserTags.md`
- Modify: `docs/checks/MET-MDO010-PriorityAccounts.md`
- Modify: `docs/checks/MET-EXO006-SubmissionPolicy.md`
- Modify: `docs/checks/MET-EXO007-TransportRuleAudit.md`

**Interfaces:**
- Consumes: Emitted branches and fields in the four matching `Checks/**` scripts.
- Produces: Check pages whose described outputs, severities, and cmdlets match every reachable branch.

- [ ] **Step 1: Rewrite MDO011 as a portal-review pointer**

Document exactly one output: `Info` at Low severity. State that neither custom tags nor tag-aware alert policies can be enumerated through MET's Exchange Online session, and direct readers to the Defender portal. Remove all Pass and Warning rows and every `Get-Tag` claim.

- [ ] **Step 2: Document MDO010's two independent results**

Describe:

```text
Priority Account Protection Toggle — High
Pass: EnablePriorityAccountProtection is true
Fail: the returned value is false, or the retrieval throws
NotApplicable: no settings object/value is returned

Priority Account Tagging — Medium
Pass: Get-User -IsVIP returns one or more users
Warning: it returns zero users
Fail: retrieval throws
```

Remove the invalid `Get-User -Filter "IsPriorityAccount -eq $true"` command and any claim that MDO010 reads anti-phishing policies.

- [ ] **Step 3: Document all EXO006 result families**

Cover the base retrieval/no-policy Fail plus:

```text
User Reported Message Settings - Report Button — High/Medium
User Reported Message Settings - SecOps Mailbox — Medium/Low
User Reported Message Settings - User Notifications — Low
User Reported Message Settings - Mailbox Address Consistency — Low
```

Describe the built-in versus third-party reporting branches, Microsoft feedback loop, three custom-mailbox flows, notification state, and address consistency without flattening them into one verdict row.

- [ ] **Step 4: Add EXO007's non-happy paths**

Document that a transport-rule retrieval exception emits Fail/Medium with Error, no enabled rules emits Info/Informational, and successfully retrieved enabled rules emit the existing audit findings.

- [ ] **Step 5: Compare pages against code and run severity parity tests**

```powershell
Invoke-Pester -Path ./Tests/Unit/DocsSeverityParity.Tests.ps1 -Output Detailed
```

- [ ] **Step 6: Commit Task 2**

```bash
git add docs/checks/MET-MDO011-UserTags.md docs/checks/MET-MDO010-PriorityAccounts.md docs/checks/MET-EXO006-SubmissionPolicy.md docs/checks/MET-EXO007-TransportRuleAudit.md
git commit -m "docs: align check pages with emitted results"
```

---

### Task 3: Repair contributor guidance and CLAUDE specification

**Files:**
- Modify: `CLAUDE.md`
- Modify: `docs/CONTRIBUTING.md`

**Interfaces:**
- Consumes: Current repository tree, CI workflow, serializer/schema, Accept Risk JavaScript, Teams003 cmdlet calls, and PR #32 metadata flow.
- Produces: Contributor instructions that lead future changes toward current repository conventions rather than recreating audit drift.

- [ ] **Step 1: Correct platform, lint, and CI instructions**

In CLAUDE:

- Use the same cross-platform DNS wording as README and retain accurate WAM guidance.
- Install PSScriptAnalyzer with `-RequiredVersion 1.25.0`.
- Keep the five-path loop and add the CI-equivalent block that prints findings and exits nonzero when any Warning or Error exists.
- Replace the stale “30%” CI description with the Ubuntu 7.4.20/7.6.6 plus Windows 7.6.6 matrix, 75% coverage gate on Ubuntu 7.6.6, and the separate Playwright browser job.

- [ ] **Step 2: Make the repository tree honest**

Add all omitted effective-policy helpers named in the design, plus `Get-METSafeSeverity`, `Get-METWorstSeverity`, certificate/assembly-conflict helpers, MDO014, `Tests/Html`, `docs/schema`, `docs/RELEASING.md`, `SECURITY.md`, `PSScriptAnalyzerSettings.psd1`, and `assets/`. If the tree remains intentionally selective, label it “key files and directories” rather than implying exhaustive coverage.

- [ ] **Step 3: Correct CLAUDE schemas and names**

- Change both “Safe Links Policy” examples to `Safe Links Effective Coverage`.
- Apply the authoritative inventory names from Task 1; EXO006 is already correct in CLAUDE and must remain so.
- Add `Info` to the JSON summary, `authentication: null` at report level, and `metadata: null` inside the example check. Keep `error: null`.

- [ ] **Step 4: Correct HTML and Teams behavior claims**

- Accept Risk stores only justification, keyed by tenant plus CheckId, Name, and AffectedObject; no acceptance date is stored.
- Teams003 uses `Get-CsTenantFederationConfiguration`, `Get-CsTeamsMeetingPolicy`, and `Get-CsTeamsChannelsPolicy`.
- Align approved verbs to `Connect`, `Disconnect`, `Expand`, `Find`, `Format`, `Get`, `Import`, `Invoke`, `New`, `Resolve`, and `Test`.

- [ ] **Step 5: Correct CONTRIBUTING conventions**

- New checks get self-contained `Tests/Unit/Checks.<ID>.Tests.ps1`; the three category files are legacy only.
- Add CLAUDE inventory synchronization to the checklist.
- Add a checklist decision for a custom `Get-METAggregationNoun` mapping and matching aggregation test when a multi-result family needs a noun other than `policies`.
- Require `Resolve-METDnsName`; forbid direct DNS cmdlet/HTTP calls in checks.
- Use the same approved-verb list as CLAUDE.
- Retain `$METCheckInfo` as the report-description source and never mention a manually maintained `CONTROLS_META` entry.

- [ ] **Step 6: Validate the corrected JSON example**

Extract the fenced JSON object under `### JSON Output Schema`, convert it with `ConvertFrom-Json`, then run:

```powershell
$json | Test-Json -SchemaFile ./docs/schema/MET-report-schema.json
```

Expected result: `True`.

- [ ] **Step 7: Commit Task 3**

```bash
git add CLAUDE.md docs/CONTRIBUTING.md
git commit -m "docs: repair contributor source of truth"
```

---

### Task 4: Finish residual machine-contract and release documentation

**Files:**
- Modify: `docs/schema/MET-report-schema.json`
- Modify: `docs/RELEASING.md`
- Modify: `Tests/Html/README.md`

**Interfaces:**
- Consumes: JSON Schema draft-07, current tag validation, package lock, and PR #30 `html-report` workflow.
- Produces: A BOM-free schema and reproducible release/browser-test instructions.

- [ ] **Step 1: Remove only the schema BOM**

Save `docs/schema/MET-report-schema.json` as UTF-8 without BOM. Do not alter schema semantics. Confirm the first byte is hexadecimal `7b` (`{`).

- [ ] **Step 2: Make the release example version-neutral**

Replace the two `v0.6.0` occurrences with a shell variable derived from the manifest so the example cannot age again:

```bash
version="$(pwsh -NoLogo -NoProfile -Command '(Import-PowerShellDataFile ./MET.psd1).ModuleVersion')"
git tag -a "v${version}" -m "Release v${version}"
git push origin "v${version}"
```

- [ ] **Step 3: Align browser-test documentation with CI**

Change `npm install` to `npm ci`. Add a `## CI` section stating that `.github/workflows/pester.yml` runs the `html-report` job on PRs and pushes to main, installs the locked dependencies with `npm ci`, installs Chromium, and runs `npm test`.

- [ ] **Step 4: Validate schema parsing and browser dependency install**

```powershell
Get-Content -Raw ./docs/schema/MET-report-schema.json | ConvertFrom-Json | Out-Null
```

```bash
cd Tests/Html
npm ci
```

- [ ] **Step 5: Commit Task 4**

```bash
git add docs/schema/MET-report-schema.json docs/RELEASING.md Tests/Html/README.md
git commit -m "docs: align schema release and browser guidance"
```

---

### Task 5: Verify the complete Section D remediation

**Files:**
- Review: all changed files
- Do not create or modify runtime/test files

**Interfaces:**
- Consumes: Tasks 1-4.
- Produces: Verification evidence and a PR-ready finding/evidence summary.

- [ ] **Step 1: Run the documented lint command**

Run the exact block now present in CLAUDE. Expected result: no findings and exit code 0.

- [ ] **Step 2: Validate the CLAUDE JSON example against the schema**

Expected result: `True` from `Test-Json -SchemaFile`.

- [ ] **Step 3: Run all PowerShell tests**

```powershell
$unit = Invoke-Pester -Path ./Tests/Unit -PassThru -Output Normal
$integration = Invoke-Pester -Path ./Tests/Integration -PassThru -Output Normal
```

Expected: unit result Passed with 1,276 passes, 2 skips, and zero failures; integration result Passed with 24 passes and zero failures.

- [ ] **Step 4: Run browser tests**

```bash
cd Tests/Html
npm test
```

Expected: all Playwright tests pass.

- [ ] **Step 5: Run documentation integrity checks**

Verify all 51 README inventory links exist, all README/CLAUDE inventory names match `$METCheckInfo.Name`, no `Get-Tag` assessment claim remains, no schema BOM remains, and the Promotions cookbook exists only under `docs/baselines`.

- [ ] **Step 6: Audit the diff allowlist**

Expected changed paths:

```text
README.md
CLAUDE.md
docs/baselines/promotions-folder.md
docs/checks/MET-EXO006-SubmissionPolicy.md
docs/checks/MET-EXO007-TransportRuleAudit.md
docs/checks/MET-MDO010-PriorityAccounts.md
docs/checks/MET-MDO011-UserTags.md
docs/CONTRIBUTING.md
docs/RELEASING.md
docs/schema/MET-report-schema.json
docs/superpowers/specs/2026-09-11-audit-section-d-design.md
docs/superpowers/plans/2026-09-11-audit-section-d.md
Tests/Html/README.md
```

- [ ] **Step 7: Prepare the PR summary**

For D-1 through D-18, state closed previously, fixed here, or intentionally unchanged, and cite the production file/line evidence behind each changed claim. Include a “Code defects found, not fixed” heading containing `None` unless implementation exposes a genuine defect.
