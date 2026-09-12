# Audit Section D Documentation Remediation Design

**Date:** 2026-09-11  
**Base:** `origin/main` at `b52313f` (PR #32)  
**Branch:** `fix/audit-section-d-docs`

## Goal

Close the remaining Section D documentation findings by making public and contributor documentation describe the code that currently ships. Keep the change documentation-only, preserve the metadata source of truth introduced by PR #32, and make the smallest README restructure that restores the product and its assessment workflow as the focus.

## Current State After PR #32

The original brief predates PRs #30 and #32. Code and documentation were re-audited against the merged `main` before this design was written.

| Finding | Current status | This branch |
|---|---|---|
| D-1 | Closed by the merged MSSP documentation | No change |
| D-2 | Partial: check metadata/report text fixed; README and check page remain stale | Fix |
| D-3 | Open | Fix |
| D-4 | Open | Fix |
| D-5 | Closed by README severity parity changes and tests | No change |
| D-6 | Closed by `$METCheckInfo.RequiresModule` plus metadata tests | No change |
| D-7 | Closed structurally: report descriptions are generated from `$METCheckInfo` | No change |
| D-8 | Partial: severity fixed; behavior remains misdocumented | Fix |
| D-9 | Partial: severity fixed; result families remain incomplete | Fix |
| D-10 | Closed at ExchangeOnlineManagement 3.7.2 | No change |
| D-11 | Partial: the path loop is fixed, but the documented tool version and blocking behavior still differ from CI | Fix |
| D-12 | Open | Fix |
| D-13 | Partial: metadata step added; CLAUDE inventory and aggregation-noun steps remain absent | Fix |
| D-14 | Open | Fix |
| D-15 | Partial | Fix against current schema and serializer |
| D-16 | Open/partial | Fix |
| D-17 | Mixed | Fix only residual items listed below |
| D-18 | Open | Fix minimally |

The clean baseline is 1,276 unit tests (2 skipped) and 24 integration tests. The brief's 1,051-unit expectation is obsolete.

## Constraints

- Documentation changes only. Do not change module behavior, checks, tests, workflows, the manifest, or module loader.
- Normal allowlist: `README.md`, `CLAUDE.md`, `ROADMAP.md`, and `docs/**`.
- Approved exception: `Tests/Html/README.md`, solely to reconcile local instructions with the browser-test CI added by PR #30.
- Do not edit `SECURITY.md`: PR #30 added npm Dependabot coverage, and its dependency claim is now correctly scoped to the shipped module.
- Do not add a `CONTROLS_META` maintenance step. PR #32 removed that parallel source of truth; HTML descriptions are generated from `$METCheckInfo.Description`.
- When the audit conflicts with current code, document current code. In particular, the JSON result's `error` value is now `null` when no error exists and the schema permits it.
- Preserve the unrelated `MET-combined.zip` and `graphify-out/` in the original checkout; all work happens in the isolated worktree.

## Documentation Changes

### 1. README safety and platform corrections

- D-2: describe MET-MDO011 as a portal-review pointer that always emits `Info` at Low severity; it does not enumerate tags or alert policies.
- D-3: state that all 51 checks run on Windows, Linux, and macOS. Document the TXT-resolution order: `Resolve-DnsName` on Windows; otherwise `dig`, `nslookup`, then configurable DNS-over-HTTPS. Mention the resolver disclosure and `MET_DOH_RESOLVER=none` opt-out.
- D-4: remove `Get-ProtectionAlert` and `Get-Tag` from the least-privilege cmdlet list because MET calls neither in its normal Exchange session.
- D-16: make all inventory names equal the authoritative `$METCheckInfo.Name` values.

### 2. README information architecture

Apply a minimal D-18 restructure:

1. Add CI/release badges and a concise “51 checks” product statement under the title.
2. Put a compact quick start before dependency and RBAC material: install, `Test-METPrerequisites`, connect, assess, and create HTML output.
3. Remove the later duplicate install/quickstart commands while retaining the detailed authentication, discovery, and scoped-run guidance under a usage heading.
4. Move the Promotions Folder cookbook intact to `docs/baselines/promotions-folder.md`. Replace its 229 README lines with a short explanation that it is an optional tenant-remediation baseline outside MET's read-only assessment behavior, plus a link.
5. Link every inventory check ID to its corresponding `docs/checks/*.md` page.
6. Add a compact options table for the exported/readability features named by D-18: `-ManagedIdentity`, `-ListChecks`, `-PassThru`, `-Detailed`, and `-SkipExchangeOnline`.
7. Correct the output-folder example to preserve dots in `contoso.onmicrosoft.com` and remove “now”.

No report screenshot will be fabricated: the repository contains no report screenshot, and `assets/**` is outside the approved edit scope. The quick start, badges, and linked inventory are the minimal D-18 front-door improvement.

### 3. Check-specific pages

- `MET-MDO011-UserTags.md`: replace impossible Pass/Warning branches with the single current Info/Low portal-review result.
- `MET-MDO010-PriorityAccounts.md`: document the High-severity protection-toggle result and the separate Medium-severity tag-presence result. Use `Get-User -IsVIP`; remove the nonexistent anti-phishing-policy assessment.
- `MET-EXO006-SubmissionPolicy.md`: document base retrieval/no-policy failures and the four named result families: Report Button, SecOps Mailbox, User Notifications, and Mailbox Address Consistency, including their actual severity ranges.
- `MET-EXO007-TransportRuleAudit.md`: add its retrieval-error Fail and no-rule Info outcomes instead of documenting only successful rule enumeration.

Pages whose severity-frontmatter issue is already enforced and green (EXO013, EXO017, and MDO014) will not be churned.

### 4. Contributor guidance

- Require new checks to use a self-contained `Tests/Unit/Checks.<ID>.Tests.ps1`; label the category-wide files as legacy homes only.
- Keep `$METCheckInfo` as the metadata/report-description source of truth.
- Add the still-manual CLAUDE inventory update and the decision/test for a custom `Get-METAggregationNoun` mapping to the add-check checklist.
- Require DNS access through `Resolve-METDnsName`, not direct `Resolve-DnsName` calls in checks.
- Align approved verbs with verbs used by the repository: `Connect`, `Disconnect`, `Expand`, `Find`, `Format`, `Get`, `Import`, `Invoke`, `New`, `Resolve`, and `Test`.

### 5. CLAUDE contributor specification

- Correct cross-platform DNS and Teams authentication wording.
- Expand the repository tree with the effective-policy resolver family, omitted helpers, MDO014, browser tests, schema/release docs, security/lint files, and assets.
- Make the lint recipe match current CI: PSScriptAnalyzer 1.25.0, all five paths, and Warning/Error findings treated as blocking.
- Correct both stale Safe Links example names and all stale inventory names.
- Make the JSON example schema-valid by adding `summary.Info`; include the serializer's `authentication` and per-check `metadata` fields, while retaining the now-correct `error: null`.
- Correct Accept Risk storage semantics: tenant plus CheckId, Name, and AffectedObject key the stored justification; no acceptance date is stored.
- Include `Get-CsTeamsChannelsPolicy` in Teams003's documented sources.
- Align the approved-verb list with CONTRIBUTING.
- Refresh the CI summary to match PR #30's PowerShell matrix, 75% coverage gate, and browser-test job.

### 6. Other residual D-17 items

- Save `docs/schema/MET-report-schema.json` as UTF-8 without a BOM.
- Replace the stale concrete `v0.6.0` release command with a manifest-derived shell variable that reads `ModuleVersion` from `MET.psd1` and uses it for the tag.
- Change `Tests/Html/README.md` from `npm install` to reproducible `npm ci` and add a short section describing the `html-report` CI job.

## Evidence and Verification

Each change will be backed by current code evidence in the eventual PR summary. Verification will include:

1. Run the exact corrected PSScriptAnalyzer command and confirm no blocking findings.
2. Extract the corrected CLAUDE JSON example and validate it with `Test-Json -SchemaFile ./docs/schema/MET-report-schema.json`.
3. Confirm the schema begins with `{`, not the UTF-8 BOM bytes.
4. Run all unit tests and compare with the 1,276-pass baseline.
5. Run all 24 integration tests.
6. Run `npm ci` and the browser suite under `Tests/Html` because its documentation is changing and PR #30 made it a CI gate.
7. Check every README inventory link resolves to an existing check page and every inventory name matches `$METCheckInfo.Name`.
8. Review the final diff against the allowlist and confirm no production or test code changed.

If documentation work exposes a production-code defect, it will not be fixed on this branch; it will be recorded under “Code defects found, not fixed” in the PR summary.
