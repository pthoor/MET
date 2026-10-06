# Changelog

All notable changes to MET are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and MET follows
[Semantic Versioning](https://semver.org/).

This file was compiled retroactively from the release notes previously
embedded in `MET.psd1`'s `PrivateData.PSData.ReleaseNotes`, which covered
v0.8.0 through v0.11.1. Release dates were not tracked at the time and are
not fabricated here. For the fuller version history, including v0.1.0
through v0.7.0, see `ROADMAP.md`.

## [Unreleased]

### Added

- MET-Teams016 (Teams Messaging Safety) reads `FileTypeCheck`,
  `UrlReputationCheck` and `ReportIncorrectSecurityDetections` from
  `Get-CsTeamsMessagingConfiguration`: Teams' built-in weaponizable file
  blocking and malicious URL warnings, which work without a Defender for
  Office 365 licence.
- MET-MDO015 (Intra-Organization Spam Filtering) reads `IntraOrgFilterState`
  on the default and enabled custom anti-spam policies and fails a policy
  that acts on no verdict at all for mail between internal users.
- MET-Teams012 now also emits a `PSTN Call Spam Filtering` result from
  `SpamFilteringEnabledType` on every Teams calling policy.
- MET-Teams006 now flags a populated `BlockedDomains` deny-list when
  `BlockAllSubdomains` is off or not returned, since blocking a domain does
  not block its subdomains by default.
- MET-Teams010 now flags non-Global external access policies that turn on
  `EnableTeamsConsumerAccess` or `EnableTeamsConsumerInbound` when the
  Global policy turns them off.

### Fixed

- MET-Teams010 warned that custom external access policies with
  `EnableFederationAccess` on were undoing a restriction on the Global policy
  even when the Global policy had federation on too. Federation is now
  compared with the Global policy, and the retired `EnablePublicCloudAccess`
  property is no longer read.

## [0.11.1] - Security and scoring correctness

### Security

- Fixed a stored cross-site scripting vulnerability in the HTML report:
  `safeHref` validated a reference URL's scheme but returned the raw string
  into an `href` attribute, so an `https` URL containing a quote could close
  the attribute and inject markup that executed when the report was opened;
  `Result`, `Severity` and `Category` were likewise interpolated unescaped
  into class attributes.
- Hardened `Connect-METSession`'s session-reuse guard, which was skipped
  entirely when no organization was specified, allowing a delegated
  connection to be reused unverified by a later bare reconnect.
- Service-principal certificates are now loaded with ephemeral key storage
  so private key material is no longer written to the on-disk key
  container.

### Fixed

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
- Fixed three defects that made a check which failed to run effectively
  invisible in the HTML report. A check carrying both a `Result` and a
  populated `Error` field (MET-Teams014 when Graph is unreachable, or any
  check `Invoke-METTriage` synthesized a Fail for after it threw) rendered
  an ordinary result badge with no indication it had failed, and the
  summary banner's Error count pointed at a card that could not be found:
  the card now renders an ERROR badge with a critical-severity border, the
  Result filter dropdown gains an Error option treated as a bucket mutually
  exclusive from the Result-based options, and the error state now takes
  precedence over the risk-accepted badge so an accepted-but-errored check
  no longer displays as a resolved finding.
- Expanding an errored card - individually or via Expand All - now
  auto-opens its "How to fix" panel, matching existing Fail/Warning
  behaviour.

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
