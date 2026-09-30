# backup-notes
backup and restore checklist for github and app center

## Offline mail recovery tool

`scripts/recover_mail.py` recovers `.eml` messages from an existing ZIP
archive (or a directory of `.eml` files), preserves the original message
bytes, extracts attachments, and builds a local, searchable index. It runs
entirely offline using only the Python standard library: it never signs in
to Microsoft, Apple, App Center, or any other service, makes no network
calls, and never executes attachments or renders remote content.

### Requirements

Python 3.8+ (standard library only, no extra packages).

### Usage

```bash
python3 scripts/recover_mail.py \
  --input /path/to/recovered-icloud-mail.zip \
  --output /path/to/local-recovery-results
```

A directory of `.eml` files is also accepted as `--input`:

```bash
python3 scripts/recover_mail.py \
  --input /path/to/recovered-eml-folder \
  --output /path/to/local-recovery-results
```

Optional safety-limit flags (all have safe defaults):

```bash
python3 scripts/recover_mail.py \
  --input recovered.zip --output results \
  --max-members 200000 \
  --max-total-size 5368709120 \
  --max-file-size 209715200 \
  --max-compression-ratio 100
```

### What it produces (all under `--output`)

- `messages/<sha256>.eml` — byte-identical copy of every unique message.
- `attachments/<hash-prefix>__<sanitized-name>` — every extracted attachment.
- `messages.csv` — date, From, To, Cc, subject, Message-ID, source paths,
  SHA-256, attachment count, parsing warnings, completeness, saved path,
  and manifest verification status.
- `attachments.csv` — attachment name, MIME type, size, SHA-256, source
  message hash, and saved relative path.
- `recovery.sqlite` — searchable headers and plain-text bodies (uses
  SQLite FTS5 when available, with an automatic fallback table otherwise).
- `summary.json` — counts, duplicates, warnings, failures, and manifest
  hash-verification results (never message bodies or secrets).
- A concise console summary (counts only — no message bodies, credentials,
  or tokens are ever printed).

### Safety behavior

- Source files are opened read-only and are never modified.
- ZIP members are validated before use: absolute paths, path traversal
  (`..`), and symlink entries are rejected; member count, per-file size,
  total expanded size, and compression ratio are all capped to defend
  against zip bombs.
- If the ZIP contains a `manifest.json` with `archive_path`/`sha256`
  entries, each listed message is verified against its recorded hash and
  any mismatch is reported explicitly (never silently ignored).
- Messages are deduplicated by exact SHA-256 of their raw bytes, not by
  Message-ID — two messages that happen to share a Message-ID but differ
  in content are always kept as distinct entries.
- Attachment files are named with a content-hash prefix, so two
  attachments that share a filename but differ in content never collide
  or overwrite each other.
- Reruns are idempotent: content-addressed message and attachment files
  are only written once and are verified (not blindly overwritten) on
  subsequent runs against the same output directory.
- Individual message parse failures are recorded and do not stop the run.
- A message is only marked "complete" when its structure (headers,
  multipart boundaries) checks out — successful parsing alone does not
  imply completeness.

### Running the tests

```bash
python3 -m unittest discover -s tests -v
```

All tests use synthetic, fabricated messages generated in-process; no real
personal data is included anywhere in the repository.

### Known limitations

- Body-text extraction for the SQLite index picks the first `text/plain`
  part it finds (or a tag-stripped `text/html` fallback for indexing
  only); it does not attempt full MIME-alternative negotiation.
- Completeness detection uses structural heuristics (boundary closure,
  required headers, parser defects) and cannot detect every form of
  truncation, e.g. a message clipped exactly at a valid boundary.
- Real recovered mail, exported archives, generated recovery results, and
  any credentials must never be committed to this repository — see
  `.gitignore`.
