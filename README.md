# backup-notes

Simple backup and restore planning notes for GitHub and Microsoft App Center.

## Purpose

This repo is a safe workspace to:
- track what data has been backed up
- track what still needs to be backed up
- write clear restore and migration steps

It is made for beginners and uses plain language.

## GitHub backup scope

Use this repo to track backups for:
- account or org repositories
- issues and pull requests
- releases and tags
- org members, teams, and settings
- SSH keys, PAT setup notes, OAuth app inventory
- connected devices/sessions checklist

## App Center backup scope

Use this repo to track:
- App Center app inventory
- any exportable analytics/diagnostics data (if still available)
- app configuration notes you can still access

Important: App Center has been retired for most services.

## What can be backed up vs restored

### Usually can be backed up
- GitHub metadata and configuration (with API exports or manual notes)
- repository content (git clone/mirror)
- App Center analytics/diagnostics exports (if available in your account)

### Cannot be fully restored from this repo alone
- live tokens/secrets (these should not be stored here)
- full App Center build/test/distribute/codepush history if it is no longer exportable
- one-click full system restore of every external service

This repo is a planning and evidence log, not a magic full-restore tool.

## Restore and migration checklist (simple order)

1. Restore GitHub repo content from backups/mirrors.
2. Re-create org/account structure (members, teams, permissions).
3. Re-create repo settings, branch rules, and integrations.
4. Re-add deploy keys, SSH keys, OAuth apps, and automation secrets safely.
5. Reconnect CI/CD and external tools.
6. For App Center, migrate workflows to current tools and use any remaining exports as reference.
7. Validate access and permissions with a test user.
8. Record what worked and what failed in this repo.

## Safety notes (tokens, secrets, private data)

- Never commit PATs, access tokens, passwords, API keys, or private certificates.
- Never commit raw private user data unless you have legal approval and protection.
- Use local `.env` files and secret managers (not git) for credentials.
- If a secret is exposed, rotate it immediately and document the incident steps.

## Starter files in this repo

- `checklist.md` -> task checklist you can mark as done
- `scripts/` -> placeholder area for future backup automation
