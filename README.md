# backup-notes

Starter repository for **backing up and restoring GitHub + App Center data** for an organization/account.

> This repo is intentionally simple and beginner-friendly. Keep it private and avoid committing exported data that includes sensitive information.

## What this repository is for

Use this repository to:
- track backup scope and limits,
- inventory what exists today,
- run/export backup tasks,
- document restore or migration steps.

## Important limitation

There is **no single full-fidelity backup/restore** for every GitHub or App Center relationship, audit trail detail, identity link, or external integration state. Some items are fully exportable, some are partial, and some must be recreated manually.

## GitHub organization backup scope

### Usually exportable / reproducible
- Repositories (clone + mirror)
- Issues and Pull Requests (API exports)
- Wiki content (git-backed wikis)
- Releases and release assets
- Basic Actions workflow metadata
- Members, teams, and team membership snapshots

### Partially exportable
- Actions artifacts/logs (retention windows, permissions, and size limits apply)
- Branch protections / rulesets / repo settings (exportable via API, restore often manual or scripted)
- Org integrations and app installations (inventory is possible; restoring trust/config may require manual re-approval)
- Security/SSO configuration details (documentable/inventory-able, but restoration may involve identity-provider and manual steps)

### Not fully restorable as-is
- Historical cross-object relationships exactly as originally timed/ordered
- Some audit/event histories after retention windows expire
- External identity/device trust relationships

## App Center backup scope

### Usually exportable / reproducible
- App inventory and app metadata
- Build logs/artifacts (while retained)
- Distribution groups and tester lists
- Integration configuration snapshots (documented settings)

### Partially exportable
- Historical build/runtime context tied to external systems
- Integration secrets/credentials (often cannot be exported in plain form)

### Not fully restorable as-is
- Full original service-side history/state after retention limits
- Device-specific install/testing relationships and some time-based activity trails

## Restore and migration notes

Use backup exports + documentation to rebuild in this order:
1. Recreate org/app structure
2. Recreate access control (members, teams, testers, groups)
3. Restore repositories/content/artifacts still available
4. Re-apply policies, protections, SSO/security settings
5. Reconnect integrations and rotate secrets/tokens
6. Validate critical workflows/builds/distributions

See:
- [`checklist.md`](./checklist.md)
- [`scripts/README.md`](./scripts/README.md)

## Task list

- [ ] Capture current GitHub org inventory
- [ ] Capture current App Center inventory
- [ ] Export repository and metadata snapshots
- [ ] Export available build/release artifacts and logs
- [ ] Document non-exportable settings and manual restore steps
- [ ] Test restore flow in a sandbox environment
