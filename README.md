# backup-notes

Backup and restore checklist for GitHub and App Center history, accounts, orgs, device access, and configuration.

## Is full backup/restore of **everything** possible?

Partially. You can back up most data and settings, but some relationship/activity data cannot be fully restored by users (platform limitations, audit/event retention, external account links).

Use this checklist to capture everything that is realistically exportable and restorable.

## Backup checklist

### 1) GitHub account + identity
- [ ] Username, primary email, backup email(s)
- [ ] 2FA method(s): authenticator app backup codes, passkeys, security keys
- [ ] Personal access tokens (names/scopes/expiry; secret values stored securely)
- [ ] SSH keys (private/public pairs) and GPG signing keys
- [ ] Connected OAuth apps and GitHub Apps list (with permissions)
- [ ] Notification settings and email preferences

### 2) GitHub repositories + code history
- [ ] Mirror clone each repo (`git clone --mirror ...`)
- [ ] Backup all branches/tags and release artifacts
- [ ] Export issues, pull requests, comments, labels, milestones
- [ ] Save Actions workflows and important run artifacts/logs
- [ ] Save branch protection and repository settings snapshots

### 3) GitHub orgs, teams, and relations
- [ ] Org membership and role(s)
- [ ] Team structure, members, maintainers, and team permissions
- [ ] Repository collaborators and access levels
- [ ] Outside collaborators and SSO/SAML requirements
- [ ] Webhooks and integrations per org/repo

### 4) Connected devices and local environment
- [ ] Device inventory (hostname, OS, disk encryption state)
- [ ] SSH config (`~/.ssh/config`), known_hosts, and agent setup
- [ ] Git config (`~/.gitconfig`, includeIf files, signing config)
- [ ] Credential manager setup (without storing raw secrets in plain text)
- [ ] Backup automation scripts/cron/systemd tasks used for sync

### 5) App Center
- [ ] App list, owners, collaborators, and org mapping
- [ ] Build/signing configuration and environment variables (secure secret store)
- [ ] Distribution groups and release history metadata
- [ ] Test/distribution settings and service connections
- [ ] Exportable audit/history data available via API/UI

### 6) Communications and account recovery
- [ ] Email addresses tied to GitHub/App Center accounts
- [ ] Archived account/security emails (ownership, login alerts, billing, org invites)
- [ ] Recovery docs: who to contact, required domains, and admin escalation path

## Restore checklist (high level)
- [ ] Recreate account security baseline first (2FA, keys, recovery methods)
- [ ] Reconnect devices and re-install signing/auth material
- [ ] Restore repositories, then org/team permissions
- [ ] Reconfigure integrations/webhooks/apps
- [ ] Reconcile non-restorable history with exported evidence (reports/log archives)

## Important limitations
- Some event histories, relationship metadata, and external links may be viewable/exportable but not re-importable.
- Token/secret values are often non-exportable after creation; rotate and store them in a dedicated secret manager.
- Keep periodic snapshots. “One-time backup” is usually not enough for account/activity recovery.
