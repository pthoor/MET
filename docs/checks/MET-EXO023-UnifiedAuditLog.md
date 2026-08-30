# MET-EXO023 - Unified Audit Log Ingestion

**Category:** EXO | **Severity:** High

## What it checks

Reads `UnifiedAuditLogIngestionEnabled` from `Get-AdminAuditLogConfig` to determine whether the tenant is writing activity to the unified audit log.

This check verifies ingestion only. It does **not** verify audit log retention duration - see the Recommendation section below for why.

## Why it matters

The unified audit log is the tenant-wide record from which mail-flow, administrative, and sign-in investigations are reconstructed. It is where the answers live to questions like which admin changed a transport rule, when a mailbox permission was granted, and which account performed a suspicious search. Individual product logs cover fragments of that picture; the unified log is what ties them into a single timeline.

With ingestion switched off, none of that is recorded. The gap is silent - nothing fails, no alert fires, and the absence is usually discovered only when someone goes looking for evidence during an incident. Switching ingestion on at that point starts a new record; it does not recover the window that went unlogged. The investigation into the event that prompted the change is precisely the investigation that cannot be run.

Because the consequence of an unconfirmed state is the same as the consequence of a disabled one, this check does not assume a safe default when the property cannot be read. Ingestion has historically shipped switched off in some tenants, so an unconfirmed state is reported as a gap to be verified rather than passed over.

## Pass / Fail / Warning

| Result | Condition |
|---|---|
| Pass | `UnifiedAuditLogIngestionEnabled` is `$true` - the tenant is writing to the unified audit log |
| Fail | `UnifiedAuditLogIngestionEnabled` is `$false` - nothing is being recorded |
| Fail | `UnifiedAuditLogIngestionEnabled` is absent - state could not be confirmed, and no safe default is assumed |
| Fail (Error) | Unable to retrieve the admin audit log configuration (permissions issue) |

## Recommendation

Enable unified audit log ingestion:

```powershell
Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
```

Confirm the resulting state:

```powershell
Get-AdminAuditLogConfig | Format-List UnifiedAuditLogIngestionEnabled
```

**Manual follow-up - retention is not asserted by this check.** How long audit records are kept is governed by audit retention policies, which are not readable over the Exchange Online connection this module uses. Ingestion being on therefore tells you records are being written, not that they will still be there when an investigation needs them. Confirm retention duration separately in the compliance portal, and set it against the realistic gap between a compromise occurring and being detected rather than against the shortest default available.

## Reference

- [Turn auditing on or off](https://learn.microsoft.com/en-us/purview/audit-log-enable-disable)
- [Set-AdminAuditLogConfig](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-adminauditlogconfig)
- [Manage audit log retention policies](https://learn.microsoft.com/en-us/purview/audit-log-retention-policies)
