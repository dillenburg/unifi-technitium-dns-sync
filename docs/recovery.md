# Recovery and operational checks

Recovery runs after Primary discovery and before normal reconciliation.

| Durable state | Observed DNS | Result |
| --- | --- | --- |
| RESERVED | Both records absent as expected | Continue creation |
| RESERVED | Intended A exists, PTR absent | Record A_CREATED and continue PTR |
| RESERVED / A_CREATED | Both intended values exist | Complete ownership |
| COMPLETE with cleanup pending | Owned old values match | Continue targeted retirement |
| Any open operation | Unexplained values | Persist CONFLICT and stop writes |

Conflicts survive restarts. Investigate the journal, stored ownership and actual
DNS together; do not delete journal rows to force progress. A reachable Secondary
is never a substitute write target when the Primary is unavailable.

## First live run

1. Keep `DRY_RUN=true` and review a full cycle, including excluded clients.
2. Resolve naming conflicts by deciding which system owns each name. Do not
   blindly delete existing records merely to satisfy a plan.
3. Back up forward/reverse zones and SQLite consistently.
4. Check zone-scoped token permissions and TLS connectivity.
5. Set `DRY_RUN=false`, restart, and observe A/PTR writes and readback.
6. On a conflict, stop and investigate before further changes.

Dry-run prevents DNS mutations and new real write reservations. It may still
update local observation/cache data; it is not a read-only SQLite mode.

## Backup and restore

Back up deployment configuration separately from secrets, all managed zones,
and the complete SQLite state. Use SQLite's online backup API or stop the
service before a file backup. Copying only a live state.db can omit WAL data.
Restore into dry-run first, inspect DNS against ownership and pending journals,
and enable writes only after review. Losing state does not authorize adoption
of already existing records. A code rollback is not a DNS rollback.

Stale cleanup uses client observation time, not DNS verification time. An absent
client must exceed `STALE_AFTER_DAYS`; only owned values that still match can be
retired. Missing observation timestamps prevent deletion.

## Validation scope

The repository tests use temporary SQLite files and fake DNS operations. They
exercise pair creation, interrupted creation, persistent conflicts, ownership
boundaries, dry-run and Primary guards. They are not a live cluster failover,
permission, backup/restore or power-loss certification. Test these separately
in your own non-production scope before rollout.
