# Backup and Restore Checklist

## 1) Prepare
- [ ] Confirm this repository is private
- [ ] Create/verify API tokens with least privilege
- [ ] Decide export location (encrypted storage + retention policy)

## 2) GitHub backup

### Fully/mostly backup-able
- [ ] Repositories (mirror clone)
- [ ] Issues + PRs (API export)
- [ ] Wiki repositories
- [ ] Releases + release assets
- [ ] Org members + teams + team memberships

### Partially backup-able
- [ ] Actions artifacts/logs (retention-limited)
- [ ] Branch protection/ruleset settings snapshot
- [ ] Org integrations/installations inventory
- [ ] SSO/security settings notes

### Not fully restorable
- [ ] Accept that full historical relationship fidelity is not guaranteed
- [ ] Record manual recreation steps for identity/integration trust

## 3) App Center backup

### Fully/mostly backup-able
- [ ] App list and basic metadata
- [ ] Available build artifacts/logs
- [ ] Distribution groups and testers

### Partially backup-able
- [ ] Integration settings snapshots
- [ ] External-secret-dependent configuration notes

### Not fully restorable
- [ ] Record gaps due to retention/device/history limitations

## 4) Restore / migration execution
- [ ] Recreate org/app skeleton
- [ ] Restore code/content/artifacts
- [ ] Reapply permissions and policies
- [ ] Reconnect integrations and rotate secrets
- [ ] Run verification checklist (builds, releases, access)
