#!/usr/bin/env python3
"""Build an offline, source-linked review timeline from Exchange trace reports.

Dates and identifiers remain artifact claims. This does not infer subscriptions,
tenant ownership, mailbox existence, or relationships between extracted identifiers.
"""
import argparse
import csv
import hashlib
import json
from datetime import timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

FIELDS = ['date_claim', 'date_claim_utc', 'date_status', 'source_path',
          'source_sha256', 'trace_sha256', 'observed_at_utc', 'billing_keyword_count',
          'identifier_occurrences', 'review_status', 'verified_event_date',
          'product', 'provider', 'account', 'tenant_id', 'subscription_reference',
          'billing_period', 'verification_source', 'review_notes']
MAX_BYTES = 20 * 1024 * 1024


def claimed_date(value):
    if not value:
        return '', 'missing'
    try:
        date = parsedate_to_datetime(value)
        if date.tzinfo is None:
            return '', 'timezone_missing'
        return date.astimezone(timezone.utc).isoformat(), 'unverified_header_claim'
    except (TypeError, ValueError, OverflowError):
        return '', 'unparseable'


def build_rows(reports):
    rows = []
    for report, digest in reports:
        if report.get('schema_version') != 1 or not isinstance(report.get('artifacts'), list):
            raise ValueError('Expected a version 1 Exchange trace report.')
        for artifact in report['artifacts']:
            if not isinstance(artifact, dict):
                raise ValueError('Invalid artifact record.')
            claim = artifact.get('date_header_claim') or ''
            normalized, date_status = claimed_date(claim)
            row = dict.fromkeys(FIELDS, '')
            row.update(date_claim=claim, date_claim_utc=normalized,
                       date_status=date_status,
                       source_path=artifact.get('source_path', ''),
                       source_sha256=artifact.get('sha256', ''), trace_sha256=digest,
                       observed_at_utc=artifact.get('observed_at_utc', ''),
                       billing_keyword_count=len(artifact.get('billing_keyword_locations', [])),
                       identifier_occurrences=json.dumps(artifact.get('candidates', []), ensure_ascii=True),
                       review_status='needs_original_source_review' if artifact.get('status') == 'inspected'
                                     else 'collection_error')
            rows.append(row)
    # Unknown dates remain explicitly undated; inspection time never substitutes.
    return sorted(rows, key=lambda row: (not bool(row['date_claim_utc']),
                                        row['date_claim_utc'], row['source_path']))


def csv_cell(value):
    value = str(value)
    # Prevent evidence text being evaluated as a spreadsheet formula on opening.
    if value.lstrip().startswith(('=', '+', '-', '@')) or value.startswith(('\t', '\r', '\n')):
        return "'" + value
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trace', action='append', required=True, help='Existing trace.json; repeat up to 100 times.')
    parser.add_argument('--output', required=True, help='New private directory, outside the repository.')
    args = parser.parse_args(argv)
    if len(args.trace) > 100:
        parser.error('At most 100 reports per run.')
    try:
        reports = []
        for name in args.trace:
            path = Path(name).expanduser()
            if path.is_symlink() or not path.is_file():
                raise ValueError('Reports must be regular files, not symlinks.')
            with path.open('rb') as handle:
                raw = handle.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise ValueError('Trace report exceeds 20 MiB.')
            report = json.loads(raw)
            if not isinstance(report, dict):
                raise ValueError('Trace report must be an object.')
            reports.append((report, hashlib.sha256(raw).hexdigest()))
        rows = build_rows(reports)
        output = Path(args.output).expanduser()
        output.mkdir(mode=0o700, parents=True, exist_ok=False)
        with (output / 'subscription-timeline.json').open('x', encoding='utf-8') as handle:
            json.dump({'schema_version': 1, 'status': 'unverified_review_worksheet',
                       'rows': rows}, handle, indent=2, ensure_ascii=True)
            handle.write('\n')
        with (output / 'subscription-timeline.csv').open('x', encoding='utf-8-sig', newline='') as handle:
            writer = csv.DictWriter(handle, fieldnames=FIELDS)
            writer.writeheader()
            writer.writerows({key: csv_cell(value) for key, value in row.items()} for row in rows)
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        parser.error(str(exc))
    print(f'Created private review worksheet: {len(rows)} source observation(s). No subscription verified.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
