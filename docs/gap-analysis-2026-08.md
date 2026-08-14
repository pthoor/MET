# Gap Analysis — 2026-08

Research pass comparing MET's shipped check inventory (26 checks as of v0.5.0) against Microsoft Learn's documented MDO/EOP mail-flow protection surface and Teams protection settings. Goal: find real, checkable gaps a tenant admin who doesn't fully understand the MDO protection stack could be missing — not cosmetic renames of existing checks.

Method: cross-referenced candidate settings against the actual check source in `Checks/MDO/`, `Checks/EXO/`, `Checks/Teams/` (not just the summary table in `CLAUDE.md`) to rule out overlap, then verified every proposed cmdlet exists and behaves as described against current Microsoft Learn documentation (linked per item below, checked 2026-08-12).

Items are tracked in `ROADMAP.md` under **v0.6.0 — Planned**. This doc holds the supporting rationale, cmdlet references, and the phased implementation plan; keep `ROADMAP.md` itself terse.

---

## Confirmed gaps

### EXO010 — Direct Send / Anonymous Relay Exposure
**Severity:** Critical · **Cmdlet:** `Get-OrganizationConfig` → `RejectDirectSend` (bool, default `$false`)

Direct Send lets unauthenticated senders (printers, scanners, legacy line-of-business apps) submit mail directly to a tenant's MX without SMTP AUTH. Following a 2025 campaign that hit 70+ organizations, attackers were found abusing the identical unauthenticated path to spoof internal colleagues — the message never crosses a connector or authenticates, so it lands as if it were internal and bypasses the anti-spoof checks MDO004 already covers (those act on `AntiPhishPolicy` authentication settings, which Direct Send traffic doesn't trigger). Microsoft shipped `RejectDirectSend` specifically to close this path. Single tenant-wide boolean, one round trip, trivial to implement.

Reference: [Set-OrganizationConfig (ExchangePowerShell)](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-organizationconfig) · [Introducing more control over Direct Send in Exchange Online](https://techcommunity.microsoft.com/blog/exchange/introducing-more-control-over-direct-send-in-exchange-online/4408790)

### EXO012 — Mailbox Forwarding & Inbox Rule Exfiltration
**Severity:** Critical · **Cmdlets:** `Get-EXOMailbox -Properties ForwardingSmtpAddress,ForwardingAddress,DeliverToMailboxAndForward` (tenant-wide, filterable server-side); `Get-InboxRule` (per-mailbox, does not scale — see implementation plan)

The classic BEC persistence technique: after a credential compromise, an attacker sets silent mail forwarding (often via an inbox rule, sometimes via the mailbox-level `ForwardingSmtpAddress` property) so they keep receiving copies of mail — invoices, wire approvals — even after the password is reset. `DeliverToMailboxAndForward=$true` makes this invisible to the victim, since a copy still lands in their own inbox. MDO007 (Anti-Spam Outbound) only checks the *tenant-wide* `AutoForwardingMode` policy toggle; it has no visibility into individual mailbox configuration, which is where real-world BEC forwarding actually lives.

Reference: [Get-EXOMailbox (ExchangePowerShell)](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-exomailbox) · [Get-InboxRule (ExchangePowerShell)](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-inboxrule)

### EXO011 — Mail Flow Connector Hygiene
**Severity:** High · **Cmdlets:** `Get-InboundConnector`, `Get-OutboundConnector`

Flags inbound connectors with `RequireTls=$false` or no `SenderIPAddresses`/`TlsSenderCertificateName` restriction — these accept anonymous or opportunistic-TLS mail and can cause messages to be treated as authenticated/internal, undermining every downstream anti-spoof and anti-phish check. Outbound connectors forcing unencrypted delivery are a related, lower-severity finding. Nothing in the current 26 checks inspects connectors at all — a genuine blind spot given connectors sit upstream of every other MDO/EOP control.

Reference: [Get-InboundConnector](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-inboundconnector) · [Get-OutboundConnector](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-outboundconnector)

### EXO013 — Spoof Intelligence Allow-List Hygiene
**Severity:** High · **Cmdlet:** `Get-TenantAllowBlockListSpoofItems -Action Allow`

MDO004 already checks whether `EnableSpoofIntelligence` is turned on, but not the actual content of the allow-list it produces. Spoof intelligence insight entries (sender/infrastructure pairs an admin has approved to spoof) accumulate over time — often auto-approved during onboarding of a legitimate third-party sender — and each one is a standing, unreviewed exception to anti-spoofing. A stale entry for a decommissioned vendor is a live phishing vector nobody's looking at.

Reference: [Get-TenantAllowBlockListSpoofItems](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-tenantallowblocklistspoofitems)

### MDO013 — Preset vs. Custom Policy Precedence Conflicts
**Severity:** High · **Cmdlets:** reuses `Get-AntiPhishPolicy`, `Get-HostedContentFilterPolicy`, etc. from MDO008, plus rule priority ordering

MDO008 already checks *coverage* gaps (which recipients aren't covered by any preset). This is a distinct failure mode: preset policies (Strict, then Standard) always take precedence over custom policies by fixed priority order, regardless of the custom policy's own priority number. A common trap is an admin building a custom policy they believe is active for a recipient, when a preset policy silently wins and applies different (sometimes weaker, sometimes just different) settings instead. Detecting this requires cross-referencing recipient overlap between preset and custom policy scopes, which MDO008's cmdlets already fetch.

Reference: [Preset security policies in EOP and Microsoft Defender for Office 365](https://learn.microsoft.com/en-us/defender-office-365/preset-security-policies)

### EXO014 — Advanced Delivery Policy Scope
**Severity:** Medium · **Cmdlets:** `Get-PhishSimOverridePolicy`, `Get-ExoPhishSimOverrideRule`

The Advanced Delivery policy exempts specified domains/IPs (third-party phishing simulation platforms) and SecOps mailboxes from all MDO/EOP filtering, ZAP, and alerting. Legitimate and necessary for running phishing simulations — but a wildcard domain entry or an overly broad IP range left over from a one-time test is an unfiltered inbound channel that bypasses MDO entirely. Nothing currently reviews this.

Reference: [Configure the advanced delivery policy](https://learn.microsoft.com/en-us/defender-office-365/advanced-delivery-policy-configure)

### EXO015 — External Sender Warning Tag
**Severity:** Medium · **Cmdlet:** `Get-ExternalInOutlook` → `Enabled`, `AllowList`

The native Outlook "External" tag on the subject line — disabled by default — is one of the cheapest, highest-value user-facing controls against lookalike-domain and BEC attacks: it lets a user visually catch "this email claims to be from my CFO but Outlook says it's external" before they act on it. It's orthogonal to every existing anti-phish/anti-spoof check, which act on the message at filter time, not on what the user sees.

Reference: [Get-ExternalInOutlook](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-externalinoutlook)

### EXO016 — ARC Trusted Sealers Review
**Severity:** Low (Informational) · **Cmdlet:** `Get-ArcConfig` → `ArcTrustedSealers`

Authenticated Received Chain (ARC) trusted sealers are legitimate for third-party services that modify messages in transit (security gateways, mailing list managers) and would otherwise break DKIM. But any domain in this list is trusted to vouch for a message's authentication results, which is effectively a bypass of normal DMARC/DKIM checks for anything it seals. There's no "correct" value to assert (empty is fine, a legitimate vendor is fine) — this should be an Info-level check that just surfaces the list for manual review, same posture as MDO011 (User Tags).

Reference: [Configure trusted ARC sealers](https://learn.microsoft.com/en-us/defender-office-365/email-authentication-arc-configure)

### Teams006 — External Access / Federation Allow-List
**Severity:** High · **Cmdlet:** `Get-CsTenantFederationConfiguration` → `AllowFederatedUsers`, `AllowedDomains`, `BlockedDomains`, `AllowTeamsConsumer`, `BlockAllSubdomains`

Open federation (allow-all-known-domains) or Teams-consumer access lets any external Teams/Skype user initiate chat with staff — a increasingly common vector for Teams-based phishing and vishing (including QR-code lures delivered via chat). Teams003 (Meeting Protection) already covers external/anonymous *meeting join*, but tenant-to-tenant chat federation is a completely separate control plane and genuinely uncovered today.

Reference: [Get-CsTenantFederationConfiguration](https://learn.microsoft.com/en-us/powershell/module/microsoftteams/get-cstenantfederationconfiguration) · [Manage external meetings and chat](https://learn.microsoft.com/en-us/microsoftteams/trusted-organizations-external-meetings-chat)

### Teams007 — Guest Messaging/Calling Configuration
**Severity:** Medium · **Cmdlets:** `Get-CsTeamsGuestMessagingConfiguration`, `Get-CsTeamsGuestCallingConfiguration`

Distinct from both federation (external tenant users) and meeting anonymous join: this is persistent guest *membership* inside teams/channels, with its own messaging and calling permission surface. Unrestricted guest messaging widens the social-engineering surface for an attacker who's obtained (or been granted) guest access. Not currently checked.

Reference: [Get-CsTeamsGuestMessagingConfiguration](https://learn.microsoft.com/en-us/powershell/module/teams/get-csteamsguestmessagingconfiguration)

### Teams008 — App Permission Policy Exposure
**Severity:** Medium (Informational lean) · **Cmdlet:** `Get-CsTeamsAppPermissionPolicy` (read-only — Microsoft's own docs say policy *creation/modification* should happen in the admin center, but `Get-` is fully supported for read access)

A default "allow all apps" assignment lets users install unreviewed third-party Teams apps carrying delegated Graph permissions — a growing OAuth-consent-phishing and supply-chain vector. This check reads the assigned policy's allow/block app lists and flags a global-allow-all posture; it does not attempt to modify anything, consistent with MET's read-only, assessment-only design.

Reference: [Get-CsTeamsAppPermissionPolicy](https://learn.microsoft.com/en-us/powershell/module/microsoftteams/get-csteamsapppermissionpolicy) · [Manage app permission policies](https://learn.microsoft.com/en-us/microsoftteams/teams-app-permission-policies)

### Enhancement — EXO001 DMARC alignment mode
**Severity:** n/a (extension, not a new check) · Same `Resolve-METDnsName` TXT lookup EXO001 already performs

EXO001 checks that a DMARC record exists and that `p=` is `quarantine` or `reject`. It doesn't currently inspect `aspf`/`adkim` (SPF/DKIM alignment mode). Relaxed alignment (`r`, the default) permits a subdomain match instead of an exact match, which is meaningfully weaker than strict (`s`) alignment. This is a few extra lines in the existing DMARC record parser, not a new check ID.

---

## Deferred — needs a dependency decision first

### Attack Simulation Training coverage
Graph beta `securityReportsRoot/getAttackSimulationTrainingUserCoverage` and `getAttackSimulationSimulationUserCoverage`, permission `AttackSimulation.Read.All`. Real gap — MDO's technical controls don't compensate for an untrained user base, and "what fraction of users have never completed a phishing simulation" is a legitimate posture signal. Held back because: (a) it's a Graph beta endpoint, not GA, and (b) it needs a Graph scope beyond what `Connect-METSession` currently requests (`Identity.SignIns`, `Groups`). Needs a maintainer decision on whether to expand the default scope set (affects every user's consent prompt) before this becomes a committed check ID.

### Secure Score correlation
`Get-MgSecuritySecureScore` via `Microsoft.Graph.Security` — not currently a MET dependency. Purely informational (cross-referencing MET's own posture score against Microsoft's Secure Score), not a pass/fail check. Lowest priority of everything surfaced in this pass; adds a new module dependency for a "nice to have" rather than closing a real detection gap.

---

## Implementation plan

Phased by severity and engineering risk, not strictly by check ID order. Each phase is independently shippable.

### Phase 1 — Critical, low engineering risk (target: v0.6.0)
- **EXO010** (Direct Send) — single property read off a cmdlet MET already calls patterns for elsewhere (`Get-OrganizationConfig`-style singleton checks exist in MDO012 via `Get-AtpPolicyForO365`). Straightforward.
- **EXO013** (Spoof intelligence allow-list) — same shape as EXO005 (TABL): list entries, flag stale/broad ones. Can largely reuse EXO005's staleness/wildcard logic.

### Phase 2 — Critical/High, needs a scoping decision (target: v0.6.0)
- **EXO012** (Mailbox forwarding & inbox rules) — the `ForwardingSmtpAddress`/`ForwardingAddress`/`DeliverToMailboxAndForward` half is a single `Get-EXOMailbox -Filter` call, cheap at any tenant size. The `Get-InboxRule` half requires one call *per mailbox* and does not scale to tenants with thousands of mailboxes inside a reasonable check runtime. Recommend shipping the mailbox-property half in v0.6.0 as EXO012, and treating inbox-rule-based forwarding as a separate, opt-in deeper scan (behind a `-Thorough` style switch, or capped to a sample) in a later release rather than blocking v0.6.0 on solving that performance problem.
- **EXO011** (Connector hygiene) — connector counts are typically small (single digits to low tens) even in large tenants, so no scaling concern; logic is a straightforward property check per connector.

### Phase 3 — High, follows MDO008 precedent (target: v0.6.0 or v0.7.0)
- **MDO013** (Preset/custom precedence conflicts) — reuses MDO008's data-fetching entirely; the new work is the precedence/overlap comparison logic. Natural to build once MDO008's `Resolve-METPresetPolicy` helper is re-examined, since this check needs the same recipient-resolution machinery.
- **Teams006** (Federation allow-list) — single cmdlet, straightforward property checks, same shape as Teams003.

### Phase 4 — Medium/Low, straightforward (target: v0.7.0)
- **EXO014** (Advanced Delivery), **EXO015** (External sender tag), **EXO016** (ARC sealers, Info-only), **Teams007** (Guest config), **Teams008** (App permission policy) — none of these have scaling or ambiguity concerns; standard single-cmdlet property checks following the existing check template (`New-METCheckResult`, try/catch, `-ErrorMessage`).
- **EXO001 enhancement** (DMARC alignment) — bundle into whichever release touches EXO001 next; small diff to an existing file, not a new check.

### Phase 5 — Deferred pending dependency decisions
- Attack Simulation Training coverage and Secure Score correlation stay in "Under Investigation" until a maintainer decides whether to take on the new Graph scope (`AttackSimulation.Read.All`) and new module dependency (`Microsoft.Graph.Security`) these require. Not scheduled to a version yet.

### Cross-cutting implementation notes
- All new checks follow the existing pattern: standalone `.ps1` in `Checks/<Category>/`, `New-METCheckResult` output shape, `try/catch` with `-ErrorMessage` (never `-Error`), no `Write-Host`.
- Each new check needs: a Pester unit test (mocked cmdlets, following `Tests/Unit/Checks.*.Tests.ps1` patterns) and a `docs/checks/MET-<ID>-<Name>.md` doc file.
- `CLAUDE.md`'s Check Inventory Detail tables and `Current State` section should be updated as part of whichever PR ships each check, not before — they document shipped state, not planned state.
- New severities feed into the existing scoring model (`Get-METCheckWeight`) unchanged — no scoring model changes needed for any item in this list.
