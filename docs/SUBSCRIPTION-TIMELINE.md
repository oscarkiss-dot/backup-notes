# Subscription evidence timeline

Run locally on Python 3.9+ after creating one or more private `trace.json` reports:

```powershell
py -3 scripts/subscription_timeline.py --trace "C:\Evidence\exchange-trace-01\trace.json" --output "$env:USERPROFILE\Desktop\subscription-review-01"
```

On macOS/Linux use `python3` and the appropriate paths. Repeat `--trace` to combine
reports. Outputs are `subscription-timeline.csv` and `subscription-timeline.json`.
The output directory must not exist. Source files and reports are never modified.
Keep outputs outside the repository; they contain personal identifiers.

## Review one original source at a time

1. Start with an original receipt, welcome email or renewal/cancellation notice.
2. Run `trace_exchange.py` on that text or EML file, then this timeline tool.
3. Open the CSV locally. It records source hashes, collection time, billing keyword
   counts, identifier occurrences and an explicitly unverified email date claim.
4. Read the original source and fill product, provider, account, subscription reference
   and billing period only where the source actually establishes them. Leave unknowns blank.
5. Fill `verification_source` with the exact page, decoded section or provider record.
   Record a corroborated event date separately in `verified_event_date`. Record uncertainty
   in `review_notes`; do not relabel all findings verified just because a file was parsed.
6. Preserve the generated JSON and original evidence; save reviewed CSV copies privately.

This is a review worksheet, not an automatic subscription detector. Each source
observation is retained, including duplicate sources across runs and collection errors.
Dates sort by timezone-aware email Date header claims, with undated rows last.
Collection timestamps and file modification times never substitute for event dates.
Text exports may contain many dates and events: this version leaves their event dates
blank and requires manual review. PDF invoices require a separate extraction/review step.

Identifiers in the same file are not automatically related. A GUID is not automatically
a tenant ID. An Azure subscription is not proof of an Exchange subscription. Personal
Outlook.com and business Microsoft 365 records must be reviewed separately. Historical
evidence must not be replaced with the configuration of a recently created tenant.

The JSON preserves original extracted values. The CSV prefixes potentially executable
spreadsheet text with an apostrophe. Neither format is redacted for public sharing.
No network access, Microsoft sign-in, mailbox export or restoration occurs here.
