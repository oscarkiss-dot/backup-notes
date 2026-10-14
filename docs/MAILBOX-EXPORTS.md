# Offline mailbox export review

Use `scripts/mailbox_exports.py` for BulkActions.txt, InboxRules.txt,
LegacySettings.txt, and CRM entity-definition XML files. Python standard library
only; no sign-in, network requests, restoration, rule changes, or executable loading.

```sh
python scripts/mailbox_exports.py --input /private/evidence/BulkActions.txt --input /private/evidence/InboxRules.txt --input /private/evidence/LegacySettings.txt --output /private/mailbox-review-new
```

The new output directory contains mailbox-review.json. Keep originals and generated
reports outside public repositories. Reports include private identifiers and raw
conditions. Do not upload evidence to GitHub Actions or commit generated reports.

Each successfully read source has a SHA-256 hash. Bulk action timestamps, state
codes, target IDs, and counts remain verbatim. No timezone is assumed and numeric
state codes are not translated into successful outcomes. ProcessedCount can exceed
TotalCount; neither is asserted to be a count of uniquely recovered messages.

Rule snapshots preserve their complete restriction and action XML. An enabled flag
in an export is not a live check. Conditions are not evaluated and addresses inside
conditions are not automatically treated as aliases or owned accounts. A date in
a rule condition is not the rule's creation date.

Legacy settings migration is distinct from mail migration and account creation.
CRM schema definitions are classified separately: field definitions and EntityId
values are not mailbox records or tenant ownership evidence. Unsupported content
is marked unrecognized; malformed/missing sources are recorded as errors. The CLI
returns nonzero if any source fails. Inputs are limited to 100 files, 10 MiB each;
UTF-8 and BOM-marked UTF-16 are supported. DTDs, XML entities, symlinks, and output
overwrites are refused. PST/OST and database formats are not parsed by this tool.

Run tests with `python -m unittest discover -s tests`.
