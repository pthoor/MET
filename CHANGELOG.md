# Changelog

All notable changes to MET are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and MET follows
[Semantic Versioning](https://semver.org/).

This file was compiled retroactively from the release notes previously
embedded in `MET.psd1`'s `PrivateData.PSData.ReleaseNotes`, which covered
v0.8.0 through v0.11.0. Release dates were not tracked at the time and are
not fabricated here. For the fuller version history, including v0.1.0
through v0.7.0, see `ROADMAP.md`.

## [Unreleased]

## [0.12.0] - Pre-1.0 audit remediation, Teams and MDO protection updates

0.11.1 was prepared but never published to PowerShell Gallery. Its changes
are included in this release, which is the first since 0.11.0.

Most of this release comes from a full pre-1.0 audit of check logic, the
module core, the HTML report, the cmdlet surface, documentation, CI/release
and the test suite. The largest class of defect it found was checks that
reported **Pass** for a setting the service never returned; those are
listed under Fixed.

### Changed

These can change existing scripts or scores - review before upgrading.

- `Invoke-METTriage` is renamed `Invoke-METAssessment`. The old name remains
  as an exported alias.
- Public functions bind parameters by name only. Positional calls such as
  `Invoke-METAssessment MET-MDO001` previously bound to the wrong parameter.
- `Get-METReport -OutputPath` with an explicit file name and extension (for
  example `./MET-report.json`) now writes exactly there. A directory, an
  extensionless path, or `-Format All` still get the timestamped
  `<timestamp>-<tenant>` run folder.
- Accepted risks in the HTML report are keyed by check ID, name and affected
  object rather than check ID alone, so accepting one result no longer
  accepts every result sharing the check ID. Acceptances stored by earlier
  versions are dropped and must be re-entered. Acceptances now also record
  the date they were made.
- Scoring:
  - An SPF record ending `?all`, or with no `all` term, is now a Fail rather
    than a Warning - RFC 7208 treats Neutral exactly like no record.
  - The forwarding family shares one severity: MET-MDO007 rises from Medium
    to High and MET-EXO012 drops from Critical to High.
  - A check that throws now scores 0 instead of being left out of the
    posture score, and an aggregated result takes the worst severity of its
    items rather than the first item's.
  - A run with nothing scorable reports a `None` band instead of 0/Critical.
- Check results display as a table by default (type name `MET.CheckResult`)
  instead of a long `Format-List` dump. JSON output is unchanged.
- Report files are written with owner-only permissions (0600 on Linux and
  macOS, a restricted ACL on Windows).
- `Invoke-METAssessment` stops with `METNotConnected` when there is no Exchange
  Online session, instead of running every check into an error.
  `-ListChecks` needs no connection.
- A `-CheckId` that matches no check, or a filter combination that matches
  nothing, now warns instead of silently running zero checks.
- `-Format HTML`/`-Format All` without `-OutputPath`, and `-Format Console`
  with `-OutputPath`, are rejected or warned about instead of dumping HTML to
  the console or silently ignoring the path.
- The minimum supported ExchangeOnlineManagement version is 3.7.2, the first
  with the `-DisableWAM` switch MET passes. `-DisableWAM` is accepted with
  every authentication mode.
- The module manifest declares `CompatiblePSEditions = @('Core')`.

### Added

- `Get-METCheck` lists every check with its name, worst-case severity,
  description and required modules, without a connection or any module
  loaded. `Invoke-METAssessment -ListChecks` now uses it, and `-CheckId`/
  `-ExcludeCheckId` tab-complete real check IDs.
- `Import-METReport` rebuilds check results from a saved JSON report, keeping
  its tenant and authentication provenance, so an HTML report can be
  re-rendered without a live tenant connection.
- `about_MET` conceptual help topic (`Get-Help about_MET`).
- Comment-based help on every exported function.
- `Test-METPrerequisites -PassThru` returns objects.
- MET-Teams016 (Teams Messaging Safety) reads `FileTypeCheck`,
  `UrlReputationCheck` and `ReportIncorrectSecurityDetections` from
  `Get-CsTeamsMessagingConfiguration`: Teams' built-in weaponizable file
  blocking and malicious URL warnings, which work without a Defender for
  Office 365 licence.
- MET-MDO015 (Intra-Organization Spam Filtering) reads `IntraOrgFilterState`
  on the default and enabled custom anti-spam policies and fails a policy
  that acts on no verdict at all for mail between internal users - including
  `Default` on a GCC High/DoD Exchange Online endpoint, where it behaves as
  `None`.
- MET-Teams012 now also emits a `PSTN Call Spam Filtering` result from
  `SpamFilteringEnabledType` on every Teams calling policy.
- MET-Teams006 now flags a populated `BlockedDomains` deny-list under open
  federation when `BlockAllSubdomains` is off (or reports it as unassessed
  when not returned), since blocking a domain does not block its subdomains
  by default. Under a specific-domain allow-list the deny-list is inactive
  and is not assessed.
- MET-Teams010 now flags non-Global external access policies that turn on
  `EnableTeamsConsumerAccess` or `EnableTeamsConsumerInbound` when the
  Global policy turns them off.
- MET-EXO001 fails `p=reject; sp=none`: subdomains left unprotected under an
  enforcing domain policy.
- HTML report:
  - Redesigned score banner and cards: the result drives a card's border and
    tint, severity is a low-key chip, and errored checks get a distinct
    striped treatment. Results are grouped under sticky, collapsible headers.
  - Top 5 Remediation Actions groups results by check and ranks by summed
    severity weight, as specified, so one check can no longer fill several
    slots.
  - Tabs, Top 5 rows and Controls table rows are keyboard operable, and the
    Accept Risk prompt is a proper modal dialog (focus trap, Escape, focus
    restore). Contrast fixes in both light and dark themes.
  - Tab counts follow the active search and filters.
  - Known cmdlet, parameter and property names render as inline code
    wherever they appear in a Finding or Recommendation.
- `MET_DOH_RESOLVER` environment variable chooses the DNS-over-HTTPS resolver
  used by MET-EXO001/EXO003 off Windows; `none` disables it.

### Security

- Fixed a stored cross-site scripting vulnerability in the HTML report:
  `safeHref` validated a reference URL's scheme but returned the raw string
  into an `href` attribute, so an `https` URL containing a quote could close
  the attribute and inject markup that executed when the report was opened;
  `Result`, `Severity` and `Category` were likewise interpolated unescaped
  into class attributes.
- `Get-METReport` could label a report with the wrong tenant after
  aggregation. Provenance now survives aggregation, and the authentication
  block is left out when results disagree about the tenant.
- Hardened `Connect-METSession`'s session-reuse guard, which was skipped
  entirely when no organization was specified, allowing a delegated
  connection to be reused unverified by a later bare reconnect. Reuse is
  also refused when two live Exchange Online sessions resolve to different
  organizations; previously only the first was checked.
- Service-principal certificates are now loaded with ephemeral key storage
  so private key material is no longer written to the on-disk key
  container.
- DNS-over-HTTPS fallback warns once per session that queried domains are
  disclosed to the resolver, can be disabled, and times out after 15 seconds.
- The tenant name or ID passed to the unauthenticated OpenID discovery lookup
  is validated and escaped before the request, which now has a 15-second
  timeout.

### Fixed

- **Checks that reported Pass without observing the setting.** A property
  the service did not return is now reported as unassessed (`Warning` or
  `NotApplicable`, with the reason in the Finding), never as a Pass:
  - MET-MDO012 passed "click-through for malicious files is blocked" when
    `AllowSafeDocsOpen` was not returned.
  - MET-Teams005 passed "all Teams messaging policies allow users to report
    security concerns" when `AllowSecurityEndUserReporting` was absent.
  - MET-MDO001 counted absent `AllowClickThrough`/`DisableURLRewrite` toward
    a Pass.
  - MET-EXO019 passed when no mailbox's per-mailbox SMTP AUTH override could
    be read.
  - MET-MDO002 (`Action`), MET-MDO006 (`BulkThreshold`), MET-EXO004,
    MET-EXO005, MET-EXO009, MET-Teams004 and MET-Teams003 (all six meeting
    settings), plus Teams012, EXO018, EXO008 and EXO021.
  - MET-EXO011, MET-EXO014 and MET-EXO016 silently dropped objects missing
    the property they filter on and reported a clean Info.
  - Fail and NotApplicable findings in MDO001, MDO002, MDO005, MDO009,
    MDO010, MDO012, EXO002, EXO006, EXO010, EXO013, EXO015 and Teams002 no
    longer state a value that was never returned.
- MET-EXO003 matched `-all` as a substring, so an include such as
  `a:mail-all.contoso.com ?all` passed as enforcing. Records are now parsed
  term by term per RFC 7208, and an incomplete DNS-lookup count is a Warning
  rather than a Pass.
- MET-EXO001 read `sp=`/`np=` as the domain policy and rejected RFC-legal
  whitespace around `=`. Records are now parsed into a tag map.
- MET-EXO005 reported a permission failure as an empty, clean list.
- MET-MDO004 returned no result at all on an empty policy set; any check
  that produces nothing now emits an explicit NotApplicable.
- MET-MDO010 left the tenant-wide protection toggle unassessed when the
  settings object came back empty.
- MET-EXO012 had no path to Pass; it now passes when no mailbox forwards and
  reports Info when every forward keeps a local copy.
- MET-EXO006 treated a multi-valued `SentTo` as a single address.
- MET-Teams003, Teams006, Teams007 and Teams008 put retrieval errors in the
  Finding and left `Error` empty.
- `Find-METRuleContradictions` threw on a recipient with no `@`.
- MET-EXO004, MET-EXO009 and MET-Teams004 now parse `Get-QuarantinePolicy`'s
  `EndUserQuarantinePermissions` string (the service returns no typed value).
  MET-EXO016 reports "none configured" when `Get-ArcConfig` returns nothing,
  as documented.
- Fixed two defects that made the posture score untrustworthy: a check that
  threw was assigned a null score and silently excluded from the weighted
  average, so a run where checks crashed could report 100/Excellent above a
  table of its own failures; and multi-result checks inherited the first
  emitted item's severity, so a leading Informational result - which
  MET-EXO001 produces for every tenant's mail.onmicrosoft.com routing
  domain - stamped the aggregate at zero weight and removed real findings
  from the score entirely.
- Fixed MET-MDO005, MET-MDO006 and MET-MDO009 resolving preset policy
  membership through the MDO/ATP rule set when the policies they assess are
  EOP-family, producing both false Fails and false Passes on tenants whose
  EOP and MDO preset scopes differ.
- Fixed MET-EXO002's key-length assertion, which read a `KeySize` property
  `Get-DkimSigningConfig` does not return, so every tenant on 1024-bit DKIM
  keys passed; it now evaluates the per-selector key sizes and asserts
  against the active signing selector so a correct mid-rotation domain is
  not failed.
- Fixed MET-EXO009, MET-Teams004 and MET-Teams005 reporting Pass while
  asserting conditions they had not verified after a partial retrieval
  failure, and MET-Teams003 flagging fully disabled Teams federation as a
  finding when MET-Teams006 recommends exactly that configuration.
- MET-Teams010 warned that custom external access policies with
  `EnableFederationAccess` on were undoing a restriction on the Global policy
  even when the Global policy had federation on too. Federation is now
  compared with the Global policy, and the retired `EnablePublicCloudAccess`
  property is no longer read.
- `Connect-METSession -ManagedIdentity` never passed `-Organization` to
  Exchange Online, which Microsoft requires for that mode.
- `Connect-METSession -CertificateThumbprint` on Linux/macOS is rejected up
  front instead of failing deep inside the connection with a misleading
  remedy.
- `-DisableWAM` is no longer passed to ExchangeOnlineManagement builds that
  do not support it.
- `Disconnect-METSession` broke the documented per-customer disconnect and
  reconnect flow for MSSPs.
- JSON reports now validate against the published schema, and
  `summary.Fail` no longer reports 0 above a table of failures.
- Console output sorts by severity weight rather than alphabetically.
- A malformed result (null or unknown severity, null timestamp) no longer
  aborts report generation.
- A failure to restrict a report file's permissions is a warning instead of
  a raw ACL error.
- `MET.psm1` fails the import when a `Public/` script cannot be loaded,
  instead of exporting a command that does not exist.
- HTML report:
  - Errored checks were effectively invisible: no ERROR badge on a card
    carrying a populated `Error`, no Error option in the Result filter, and
    an accepted-but-errored check shown as resolved. An errored check's
    Recommendation is now shown alongside the error, and its "Details"
    panel opens with Expand All.
  - An empty report no longer shows a score of 0 in the Critical band.
  - A corrupt stored score no longer shows `NaN` in the score delta.
  - A very long Accept Risk justification no longer silently fails to save.
- The release package now includes `MET.Format.ps1xml` and the `about_MET`
  help topic.

## [0.11.0] - Mail-flow, authentication-surface and audit coverage

### Added

- Seven checks for control planes MET previously had no visibility into:
  - MET-EXO018 (Remote Domain Automatic Forwarding) closes the third and
    last automatic-forwarding control plane alongside the outbound spam
    policy and per-mailbox forwarding, so a tenant whose default remote
    domain permits forwarding to every external domain is no longer scored
    clean.
  - MET-EXO019 (SMTP Client Authentication) reports legacy SMTP AUTH
    tenant-wide and enumerates per-mailbox overrides that re-enable it.
  - MET-EXO020 (Connection Filter Policy Hygiene) reports IP allow-list
    entries and the third-party safe list, both of which bypass spam
    filtering and spoof intelligence.
  - MET-EXO021 (Mailbox Audit Logging) and MET-EXO023 (Unified Audit Log
    Ingestion) report the audit state a compromise investigation depends
    on, neither of which can be backfilled after the fact.
  - MET-EXO022 (Calendar and Contact Sharing) reports calendar detail and
    contacts exposed to all domains or anonymously.
  - MET-Teams015 (Teams Email Integration) reports channel email
    addresses, a mail ingress path that never traverses the mailbox
    delivery path and so is unaffected by Exchange transport rules.
- The first automated test coverage of the HTML report, including
  injection-safety assertions and browser-driven verification of its
  filtering and risk-acceptance behaviour.

### Changed

- Enhanced three existing checks: MET-MDO005 now inspects the contents of
  the common attachment filter rather than only whether it is enabled,
  MET-MDO003 now covers impersonation protection for named external
  partner domains, and MET-Teams003 now covers external screen-control
  requests and anonymous meeting starts.

## [0.10.0] - Connect-METSession security hardening

### Security

- Fixed a confirmed cross-customer data leak in session reuse:
  `Connect-METSession` previously reused any live Exchange
  Online/Graph/Teams connection without verifying it belonged to the
  requested tenant, so running MET against two different
  `-DelegatedOrganization` customers in the same session without
  disconnecting in between could return a report labeled for one customer
  containing another customer's actual configuration.

### Added

- Certificate-file authentication (`-CertificatePath`/`-CertificatePassword`)
  for non-Windows platforms, since `-CertificateThumbprint` is
  Windows-only.
- `Disconnect-METSession` for clean session teardown across all three
  connection legs.
- MET-MDO014 (Group Reference Audit); expanded MET-EXO014 (Advanced
  Delivery Policy) coverage.

### Changed

- Scoped device-code authentication down to a documented headless-only
  fallback, with a warning on every use, per Microsoft's current guidance
  to block it wherever possible.

## [0.9.0] - Quarantine policy accuracy pass

### Fixed

- Two confirmed false-positive bugs: MET-EXO009 previously flagged
  Microsoft's own Standard/Strict preset security policies as
  Fail/Warning for impersonation, spoof, and phish quarantine verdicts,
  even though Microsoft's own Strict preset uses full-access quarantine
  policies for those verdicts by design; corrected to only evaluate the
  two verdicts (Malware, High-Confidence Phish) that actually have a
  restrictive floor.
- MET-EXO004 previously flagged the built-in `AdminOnlyAccessPolicy`'s
  by-design "no access" configuration as a misconfiguration on every
  tenant; narrowed to evaluate only genuinely custom quarantine policies.

### Added

- Preset-aware retention handling to MET-EXO008.
- A new informational check, MET-EXO017 (Quarantine Notification
  Cadence).

## [0.8.0] - Teams attack-surface hardening

### Added

- Five new Teams checks: MET-Teams009 (Trial Tenant Federation Exposure),
  MET-Teams010 (Per-User External Access Policy Drift), MET-Teams011
  (SecOps Blocklist Authority & Blocked Entities), MET-Teams012 (Call
  Reporting / vishing surface), and MET-Teams014 (Cross-Tenant Guest &
  External Collaboration, the first check with a direct Microsoft Graph
  dependency).
- Rule-level exception visibility to MET-Teams001 and MET-Teams004.

### Fixed

- A real gap in MET-Teams003, which previously only evaluated the Global
  meeting policy and missed custom meeting policies entirely.
