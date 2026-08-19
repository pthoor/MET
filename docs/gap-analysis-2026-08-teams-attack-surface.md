# Gap Analysis — 2026-08 — Teams Attack-Surface Posture

Research pass triggered by an external draft (`docs/checks-suggestions.md`) proposing 14 new Teams checks derived from Teams attack-chain planning work (Storm-1811/Black Basta/3AM helpdesk vishing, APT29/Midnight Blizzard external-tenant first contact, DarkGate-style chat lures, meeting-invite and malicious-app delivery). Goal: separate what's genuinely uncovered from what MET's existing 8 Teams checks already do, and verify every cmdlet/property claim against current Microsoft Learn docs before committing anything to a check ID.

Method: read every check in `Checks/Teams/` in full (not just the `CLAUDE.md` summary table) to find real overlap, then verified each proposed cmdlet/property against Microsoft Learn (checked 2026-08-18). The source draft uses its own result schema (`Status`/`Observed`/`Expected`/`Impact`/`AttackMapping`/`Baseline`, IDs like `MET-TEAMS-001`) that does not match MET's actual `New-METCheckResult` contract (`Result`/`Severity`/`AffectedObject`/`Finding`/`Recommendation`/`ReferenceUrl`, IDs like `MET-Teams009`) or its Pass/Fail/Warning/Info/NotApplicable result vocabulary (no `Manual`) — every adopted item below is normalized to MET's real contract.

Items are tracked in `ROADMAP.md` under **v0.8.0 — Planned**.

---

## Overlap disposition (all 14 draft items)

| Draft ID | Disposition | Detail |
|---|---|---|
| TEAMS-001 (consumer inbound) | Folds into **Teams006 enhancement** | Teams006 (`ExternalAccess.ps1:19-21`) checks `AllowTeamsConsumer` only. Add `AllowTeamsConsumerInbound` + `RestrictTeamsConsumerToExternalUserProfiles`. |
| TEAMS-002 (federation allowlist) | Folds into **Teams006 enhancement** | Teams006 (`:7-18`) already fails on `AllowFederatedUsers=$true` + `AllowedDomains=AllowAllKnownDomains` — same logic as drafted. Gap: never checks `BlockedDomains` emptiness. Add it. |
| TEAMS-003 (trial-tenant federation) | **New: Teams009** | `ExternalAccessWithTrialTenants` not read anywhere in the codebase. |
| TEAMS-004 (per-user policy drift) | **New: Teams010** | `Get-CsExternalAccessPolicy` not read anywhere. |
| TEAMS-005 (SecOps blocklist authority) | **New: Teams011** | Nothing reads `SecurityTeamAllowBlockListDelegation` or `Get-CsTeamsExternalAccessConfiguration` today. |
| TEAMS-006 (Teams reporting on) | **No action** | Teams005 (`TeamsUserReporting.ps1:31-46`) already enumerates every `Get-CsTeamsMessagingPolicy` instance and fails on `AllowSecurityEndUserReporting=$false` — identical to the draft. |
| TEAMS-007 (Defender submission routing) | **No action** | Teams005 (`:17-25`) already checks `ReportChatMessageEnabled` and, when enabled, requires `ReportChatMessageToCustomizedAddressEnabled`. The draft's proposed `ReportChatMessageAddresses` property **does not exist** per Microsoft Learn — the draft was wrong here, not MET. |
| TEAMS-008 (call reporting) | **New: Teams012** | `Get-CsTeamsCallingPolicy` not read anywhere. |
| TEAMS-009 (Safe Links for Teams) | Folds into **Teams001 enhancement** | Teams001 already fails when no policy has `EnableSafeLinksForTeams=$true`. Gap (self-flagged in the draft too): never verifies a `Get-SafeLinksRule` actually targets the policy — a policy with the flag on but no assigning rule is not applied. |
| TEAMS-010 (Safe Attachments Teams/SPO/ODB) | **No action** | Teams002 already checks both the global `EnableATPForSPOTeamsODB` *and* per-policy `EnableSafeAttachmentsForTeams` — strictly more than the draft covers. |
| TEAMS-011 (Teams protection policy / ZAP) | Folds into **Teams004 enhancement** | Teams004 already checks `ZapEnabled` + quarantine-tag release permission. Gap: never calls `Get-TeamsProtectionPolicyRule`, so rule-scope/exclusions are invisible. |
| TEAMS-012 (meeting anon/auto-admit/lobby) | Folds into **Teams003 enhancement** | Teams003 (`MeetingProtection.ps1:21`) filters to `Identity -eq 'Global'` only — **a real gap**, contradicts the project's own "enumerate all policy instances" rule (`CLAUDE.md`). Custom meeting policies are invisible today. Remove the filter; add `AllowPSTNUsersToBypassLobby`. |
| TEAMS-013 (app/bot governance, ACM-aware) | Split — see below | Legacy-policy part duplicates Teams008 exactly. ACM-awareness and Graph app-catalog enumeration are new but blocked on scope/detection gaps — see **Deferred**. |
| TEAMS-014 (guest messaging + cross-tenant) | Split | Guest messaging/calling duplicates Teams007 exactly. Cross-tenant access policy (Graph) is new — **New: Teams014**. |

---

## Confirmed gaps (committed, v0.8.0)

### Teams009 — Trial Tenant Federation Exposure
**Severity:** High · **Cmdlet:** `Get-CsTenantFederationConfiguration` → `ExternalAccessWithTrialTenants`

Storm-1811-style campaigns spin up a disposable trial tenant to look like a clean external sender. The property is a string enum (`ExternalAccessWithTrialTenantsType`, **not boolean** — the draft flagged this as unconfirmed and was right to). Confirmed values: `Allowed` / `Blocked`, secure = `Blocked`. Companion `AllowedTrialTenantDomains` lets an admin safelist specific trial domains while keeping the default blocked — surface it in the finding as a mitigating factor.

Reference: [Set-CsTenantFederationConfiguration](https://learn.microsoft.com/en-us/powershell/module/microsoftteams/set-cstenantfederationconfiguration)

### Teams010 — Per-User External Access Policy Drift
**Severity:** Medium · **Cmdlet:** `Get-CsExternalAccessPolicy` (enumerate all non-Global instances)

A locked-down tenant-wide federation config (Teams006) means nothing if a custom `CsExternalAccessPolicy` re-opens it for a specific user set. **Verify before coding:** Microsoft Learn's cmdlet reference only documents `EnableFederationAccess` and `EnablePublicCloudAccess` as confirmed output properties (via its own usage examples) — the draft's proposed `EnableTeamsConsumerInbound` and `CommunicationWithExternalOrgs` properties are **not** confirmed anywhere in current docs. Build the Fail condition against the two confirmed properties (`EnableFederationAccess=$true` and/or `EnablePublicCloudAccess=$true` on a non-Global policy while the tenant baseline is restrictive) and dump `Get-CsExternalAccessPolicy | Select-Object *` against a live tenant before finalizing — the other two properties may exist under different names or may not exist at all on current module versions.

Blast-radius correlation via `Get-CsOnlineUser -Filter` (assigned-user counts) is valuable but should ship as a best-effort addition, not a hard dependency — same "doesn't scale to per-object enumeration" caution as EXO012's inbox-rule scope decision.

Reference: [Get-CsExternalAccessPolicy](https://learn.microsoft.com/en-us/powershell/module/microsoftteams/get-csexternalaccesspolicy)

### Teams011 — SecOps Blocklist Authority & Blocked Entities
**Severity:** Medium (Warning, not hard Fail — response-readiness signal) · **Cmdlets:** `Get-CsTenantFederationConfiguration` → `SecurityTeamAllowBlockListDelegation`; `Get-CsTeamsExternalAccessConfiguration` → `BlockedUsers`/`BlockExternalAccessUserAccess`

The draft guessed the wrong cmdlet for this (it proposed the toggle lives on `Get-CsTeamsExternalAccessConfiguration`). Verified: the delegation toggle is actually `SecurityTeamAllowBlockListDelegation` on `Get/Set-CsTenantFederationConfiguration` (enum `Enabled`/`Disabled`, default `Disabled`) — when `Enabled`, SecOps can add domains/users to the blocklist directly from the Defender portal during an active incident. `Get-CsTeamsExternalAccessConfiguration` is a real, current, separate cmdlet whose `Set-` counterpart exposes `BlockExternalAccessUserAccess` (bool) and `BlockedUsers` (list) — use it for the "what's currently blocked" half of the finding.

Reference: [Set-CsTenantFederationConfiguration](https://learn.microsoft.com/en-us/powershell/module/microsoftteams/set-cstenantfederationconfiguration) · [Get-CsTeamsExternalAccessConfiguration](https://learn.microsoft.com/en-us/powershell/module/microsoftteams/get-csteamsexternalaccessconfiguration) · [Set-CsTeamsExternalAccessConfiguration](https://learn.microsoft.com/en-us/powershell/module/microsoftteams/set-csteamsexternalaccessconfiguration)

### Teams012 — Call Reporting (Vishing Surface)
**Severity:** Medium · **Cmdlet:** `Get-CsTeamsCallingPolicy` → `ReportCall`

Closest native control to the Storm-1811/3AM helpdesk-vishing vector — "report a call" as a suspicious action. Verified property name and type: `ReportCall` is a **string** (not boolean), default `Enabled`. Enumerate all in-use calling policies, not just Global.

Reference: [New-CsTeamsCallingPolicy](https://learn.microsoft.com/en-us/powershell/module/microsoftteams/new-csteamscallingpolicy)

### Teams014 — Cross-Tenant Guest & External Collaboration Restrictions
**Severity:** Medium · **Source:** Microsoft Graph `GET /policies/crossTenantAccessPolicy`, `GET /policies/authorizationPolicy`

Genuinely distinct control plane from Teams007's guest chat/calling capability and Teams006's federation config: this is Entra's cross-tenant access default + partner overrides, and whether guests/external users can bypass the resource tenant's own protection policies. No Exchange Online or native Teams-module equivalent exists for this data, satisfying `CLAUDE.md`'s bar for adding a direct Graph dependency. **Verified: requires only `Policy.Read.All`**, which `Connect-METSession` already requests — no scope expansion needed. Must degrade non-fatally (emit `NotApplicable` with the retrieval error, not throw) exactly like `Expand-METGroupMembership` does when Graph is unavailable — this will be the first *check* (not just a private helper) to call Graph directly, so the degrade pattern needs to live in the check itself, not a shared function.

Reference: [Get crossTenantAccessPolicy](https://learn.microsoft.com/en-us/graph/api/crosstenantaccesspolicy-get) (confirms `Policy.Read.All` as least-privileged permission)

---

## Enhancements to existing checks (no new CheckId)

| Check | Change | Why not a new check |
|---|---|---|
| Teams001 (Safe Links) | Verify a `Get-SafeLinksRule` actually targets each policy with `EnableSafeLinksForTeams=$true` | Same control, same cmdlet family — a policy/rule pairing gap, not a new surface. Matches the project's existing "rule + policy pairing" design note. |
| Teams003 (Meeting Protection) | Remove the `Identity -eq 'Global'` filter (`MeetingProtection.ps1:21`) to enumerate all meeting policies; add `AllowPSTNUsersToBypassLobby` | This is a real blind spot in shipped code, not a new feature — custom meeting policies are invisible today, contradicting the project's own "enumerate all policy instances" rule. |
| Teams004 (ZAP for Teams) | Add `Get-TeamsProtectionPolicyRule` scope/exclusion check | Same policy family; rule exceptions can silently exempt recipients ZAP is supposed to cover. |
| Teams006 (External Access) | Add `AllowTeamsConsumerInbound`, `RestrictTeamsConsumerToExternalUserProfiles`, and `BlockedDomains`-emptiness | Same cmdlet already called; these are properties on the same response object Teams006 doesn't yet read. |
| Teams008 (App Permission Policy) | Add a caveat line in `Recommendation` noting that on tenants migrated to App Centric Management (ACM), `Get/Set-CsTeamsAppPermissionPolicy` are documented as inert ("do not use" for Set; may report a stale/misleading Pass) | **Not** a code-logic change — no Microsoft Learn source documents a cmdlet or property to *detect* ACM migration state itself, so real ACM-awareness can't be built reliably today. Doc-only caveat until a detection method is confirmed (see Deferred). |

---

## Deferred — needs a scope or detection-method decision (`ROADMAP.md` → Under Investigation)

| Item | Blocker |
|---|---|
| Risky Teams app/bot catalog enumeration (draft TEAMS-013 part 3) | Confirmed working endpoint is Graph `GET /appCatalogs/teamsApps`, but it requires `AppCatalog.Read.All` — **not** in `Connect-METSession`'s current scope set (`Policy.Read.All`, `Organization.Read.All`, `Group.Read.All`, `User.Read.All`). Same pattern as the existing Attack Simulation Training entry: needs an explicit decision to expand the Graph scope set before committing to a check ID. |
| ACM migration-state detection | No confirmed cmdlet or Graph property exists to read whether a tenant has migrated to App Centric Management. Without it, Teams008 can't reliably distinguish "compliant legacy policy" from "inert legacy policy on a migrated tenant." Revisit if Microsoft documents a detection surface. |
| Org-wide third-party app enablement / custom-app sideloading toggle | Draft TEAMS-013 part 2 assumed "the durable read path is Graph" — research found no confirmed Graph endpoint for this specific org-wide toggle (it lives in Teams admin center org-wide app settings). Stays open. |

---

## Known limitation — not buildable as a check

### AIR (Automated investigation and response) auto-remediation settings

Confirmed: **no supported PowerShell cmdlet and no public Microsoft Graph API** reads or sets AIR auto-remediation configuration. [Automated remediation in AIR](https://learn.microsoft.com/en-us/defender-office-365/air-auto-remediation) documents portal-only configuration (unusual for an MDO/EOP feature doc — no cmdlet cross-reference at all), and the Graph Security API (`security/alerts`, `security/incidents`, beta `securityAction`) has no `automatedInvestigation`/`airConfiguration` resource in v1.0 or beta. This matches the observed behavior: the portal UI is backed by an internal endpoint (`/apiproxy/di/Find/AirConfiguration?tenantid=<tenantId>`) with no supported public surface — there's genuinely nothing for a check to call.

**Not implemented as a MET check** — a check with no data source would emit identical static content on every run regardless of actual tenant state, which doesn't fit the assessment model (and MET's `Result` enum has no `Manual` value to represent "couldn't be checked, go look yourself" the way the draft's invented schema assumed). Documented instead as a manual-review item:

- **Portal path:** Settings → Email & collaboration → MDO automation settings (`https://security.microsoft.com/securitysettings/mdoAutomationSettings`)
- **What it actually configures:** an opt-in toggle per message-cluster type (*Similar files*, *Similar URLs*, *Multiple similar attributes*), all mapped to one action — **Soft delete** (to Recoverable Items). Clusters over 10,000 messages always require manual approval in the Action Center regardless of this setting.
- **Baseline:** Microsoft has not published this as part of the Standard/Strict preset tables, so there's no single "correct" value to assert — general guidance is that enabling it speeds remediation for these three well-understood high-confidence cluster types, at the cost of the mailbox's normal deleted-item retention window being the only recovery path. Treat as an org-specific speed-vs-recoverability trade-off, not a Microsoft-mandated setting.

Recommend adding a short "Manual Review Items" section to `README.md` (or a `docs/manual-review.md`) covering this, cross-referenced from the check inventory so users know it's a deliberate scope boundary, not an oversight.

---

## Implementation plan

Same pattern as v0.6.0: parallel subagent dispatch, one check = one self-contained `.ps1` + one self-contained `Tests/Unit/Checks.<ID>.Tests.ps1` + one `docs/checks/*.md`, no shared files touched per check to avoid merge conflicts. Enhancements to existing checks touch one file each (check + its existing test file) and should land as separate commits/PRs from the net-new checks so a regression is easy to bisect.

1. **Enhancements first** (lower risk, no new files, fixes two real gaps — Teams003's Global-only filter and Teams008's ACM caveat): Teams001, Teams003, Teams004, Teams006, Teams008.
2. **New checks**, in dependency order (Teams011 reuses the federation config Teams009 also reads, so sequence them together to avoid redundant round-trips if `$METContext` gains a shared federation-config cache): Teams009, Teams011, Teams010, Teams012, Teams014.
3. **Docs-only**: AIR manual-review section.
4. Update `CLAUDE.md`'s Teams check inventory table and `ROADMAP.md` on completion, matching the v0.6.0/v0.7.0 entries' style.

All new/changed Fail conditions must be validated against a live tenant (or at minimum a mocked property dump matching `Select-Object *` output) before merging — three items above (Teams010's exact property names, Teams009's `AllowedTrialTenantDomains` interaction, Teams011's `SecurityTeamAllowBlockListDelegation` default) are corrected from the original draft but not yet tenant-verified.
