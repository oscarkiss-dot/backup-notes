import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('timeline', Path(__file__).resolve().parents[1] / 'scripts/subscription_timeline.py')
timeline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(timeline)


class TimelineTests(unittest.TestCase):
    def artifact(self, date=None):
        return {'status': 'inspected', 'source_path': 'fabricated.eml',
                'sha256': 'a' * 64, 'date_header_claim': date,
                'observed_at_utc': '2026-10-14T00:00:00+00:00',
                'candidates': [{'kind': 'email', 'value': 'sample@example.invalid'}],
                'billing_keyword_locations': [{'section': 'body', 'line': 1}]}

    def test_claims_never_become_confirmed_links(self):
        rows = timeline.build_rows([({'schema_version': 1, 'artifacts': [self.artifact('Mon, 04 Jan 2021 10:00:00 -0500')]}, 'b' * 64)])
        row = rows[0]
        self.assertEqual(row['date_claim_utc'], '2021-01-04T15:00:00+00:00')
        self.assertEqual(row['date_status'], 'unverified_header_claim')
        for field in ('product', 'provider', 'account', 'tenant_id', 'subscription_reference', 'verified_event_date'):
            self.assertEqual(row[field], '')
        self.assertEqual(row['source_sha256'], 'a' * 64)

    def test_unknown_and_timezone_missing_dates_stay_unknown(self):
        for value, status in [(None, 'missing'), ('not a date', 'unparseable'), ('4 Jan 2021 10:00:00', 'timezone_missing')]:
            self.assertEqual(timeline.claimed_date(value), ('', status))

    def test_sort_uses_claim_not_collection_time_and_preserves_errors(self):
        a = self.artifact()
        a['status'] = 'error'
        b = self.artifact('Mon, 04 Jan 2021 10:00:00 +0000')
        rows = timeline.build_rows([({'schema_version': 1, 'artifacts': [a, b]}, 'hash')])
        self.assertEqual(rows[0]['date_claim_utc'], '2021-01-04T10:00:00+00:00')
        self.assertEqual(rows[1]['review_status'], 'collection_error')
        self.assertEqual(rows[1]['date_claim_utc'], '')

    def test_spreadsheet_formula_escaping(self):
        for value in ('=1+1', ' @SUM(1,2)', '+1', '-1', '\tformula'):
            self.assertTrue(timeline.csv_cell(value).startswith("'"))
        self.assertEqual(timeline.csv_cell('normal'), 'normal')

    def test_cli_preserves_input_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'trace.json'
            source.write_text(json.dumps({'schema_version': 1, 'artifacts': [self.artifact()]}))
            before = source.read_bytes()
            output = root / 'output'
            args = ['--trace', str(source), '--output', str(output)]
            self.assertEqual(timeline.main(args), 0)
            result = json.loads((output / 'subscription-timeline.json').read_text())
            self.assertEqual(result['rows'][0]['trace_sha256'], hashlib.sha256(before).hexdigest())
            self.assertEqual(source.read_bytes(), before)
            with self.assertRaises(SystemExit):
                timeline.main(args)


if __name__ == '__main__':
    unittest.main()
