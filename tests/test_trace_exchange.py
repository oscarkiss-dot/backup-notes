import contextlib
import hashlib
import importlib.util
import io
import json
import tempfile
import unittest
import urllib.error
from email.message import EmailMessage
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('trace_exchange', Path(__file__).parents[1] / 'scripts/trace_exchange.py')
trace = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(trace)
TENANT = '11111111-2222-3333-4444-555555555555'


class TraceTests(unittest.TestCase):
    def test_domain_and_uuid_normalization(self):
        self.assertEqual(trace.normalize_target(' Example.onmicrosoft.com. '), 'example.onmicrosoft.com')
        self.assertEqual(trace.normalize_target(TENANT), TENANT)

    def test_rejects_urls_emails_injection_shared_domains_and_malformed_ids(self):
        for value in ['https://example.com', 'user@example.com', 'example.com/path',
                      'example.com?token=secret', '-type=TXT', '127.0.0.1', 'hotmail.com',
                      'outlook.com', 'onmicrosoft.com', 'example..com', 'x.com\n--help',
                      '11111111-2222-3333-4444-55555555555']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                trace.normalize_target(value)

    def test_inspection_preserves_source_and_records_provenance(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'invoice.txt'
            raw = f'Invoice\nowner@example.onmicrosoft.com\nID {TENANT}\n'.encode()
            source.write_bytes(raw)
            result = trace.inspect_file(source)
            self.assertEqual(source.read_bytes(), raw)
            self.assertEqual(result['sha256'], hashlib.sha256(raw).hexdigest())
            self.assertEqual(result['historical_status'], 'unverified')
            self.assertEqual(result['billing_keyword_locations'], [{'section': 'text', 'line': 1}])
            self.assertIn({'kind': 'unclassified_guid', 'value': TENANT, 'section': 'text',
                           'line': 3, 'status': 'observed_in_artifact_only'}, result['candidates'])

    def test_mime_decoding_and_attachment_exclusion(self):
        with tempfile.TemporaryDirectory() as folder:
            msg = EmailMessage()
            msg['Date'] = 'Tue, 01 Jan 2019 12:00:00 +0000'
            msg.set_content('Microsoft 365 invoice for owner@example.onmicrosoft.com', cte='base64')
            msg.add_attachment(b'secret@attachment.example', maintype='text', subtype='plain', filename='secret.txt')
            source = Path(folder) / 'message.eml'
            source.write_bytes(msg.as_bytes())
            result = trace.inspect_file(source)
            self.assertTrue(result['date_header_claim'])
            self.assertTrue(any(c['value'] == 'owner@example.onmicrosoft.com' for c in result['candidates']))
            self.assertFalse(any(c['value'] == 'secret@attachment.example' for c in result['candidates']))
            self.assertEqual(result['historical_status'], 'unverified')

    def test_utf16_export(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'export.txt'
            source.write_bytes('user@example.onmicrosoft.com'.encode('utf-16'))
            self.assertEqual(trace.inspect_file(source)['status'], 'inspected')
            self.assertEqual(len(trace.inspect_file(source)['candidates']), 2)

    def test_missing_unsupported_oversized_and_symlink_inputs(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.assertEqual(trace.inspect_file(root / 'missing.txt')['status'], 'error')
            pdf = root / 'invoice.pdf'
            pdf.write_bytes(b'%PDF')
            self.assertEqual(trace.inspect_file(pdf)['status'], 'error')
            big = root / 'large.txt'
            big.write_bytes(b'12345')
            with patch.object(trace, 'MAX_FILE_BYTES', 4):
                self.assertEqual(trace.inspect_file(big)['status'], 'error')
            link = root / 'link.txt'
            try:
                link.symlink_to(big)
            except OSError:
                return
            self.assertEqual(trace.inspect_file(link)['status'], 'error')

    def test_offline_cli_never_calls_network(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / 'notes.txt'
            source.write_text('secret-body owner@example.onmicrosoft.com', encoding='utf-8')
            console = io.StringIO()
            with patch.object(trace, 'fetch_json', side_effect=AssertionError('network')), \
                 patch.object(trace, 'query_dns', side_effect=AssertionError('dns')), \
                 contextlib.redirect_stdout(console):
                code = trace.main(['--evidence', str(source), '--output', str(root / 'result')])
            self.assertEqual(code, 0)
            report = json.loads((root / 'result/trace.json').read_text())
            self.assertEqual(report['discovery'], [])
            self.assertNotIn('secret-body', (root / 'result/trace.json').read_text())
            self.assertNotIn('owner@', console.getvalue())

    def test_existing_output_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as folder, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                trace.main(['--evidence', 'missing.txt', '--output', folder])

    def test_online_consent_is_required(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            trace.main(['--domain', 'example.onmicrosoft.com', '--output', 'unused'])

    def test_missing_evidence_is_reported_with_nonzero_exit(self):
        with tempfile.TemporaryDirectory() as folder, contextlib.redirect_stdout(io.StringIO()):
            output = Path(folder) / 'result'
            self.assertEqual(trace.main(['--evidence', str(Path(folder) / 'no.txt'), '--output', str(output)]), 2)
            self.assertEqual(json.loads((output / 'trace.json').read_text())['artifacts'][0]['status'], 'error')

    def test_oidc_metadata_does_not_claim_mailbox_or_ownership(self):
        getter = lambda url: ({'issuer': f'https://login.microsoftonline.com/{TENANT}/v2.0'}, 'hash')
        result = trace.discover('example.onmicrosoft.com', getter=getter)
        self.assertEqual(result['tenant_id'], TENANT)
        self.assertEqual(result['status'], 'current_tenant_metadata_observed')
        for field in ('historical_status', 'mailbox_status', 'ownership_status'):
            self.assertEqual(result[field], 'not_established')

    def test_consumer_authority_never_becomes_personal_tenant(self):
        result = trace.discover('example.onmicrosoft.com', getter=lambda url: (
            {'issuer': f'https://login.microsoftonline.com/{trace.CONSUMER_TENANT}/v2.0'}, 'hash'))
        self.assertEqual(result['status'], 'shared_consumer_authority')

    def test_unexpected_issuer_is_not_trusted(self):
        for issuer in [None, [], 'https://evil.example/' + TENANT,
                       'https://login.microsoftonline.com/{tenantid}/v2.0']:
            with self.subTest(issuer=issuer):
                result = trace.discover('example.onmicrosoft.com', getter=lambda url: ({'issuer': issuer}, 'hash'))
                self.assertEqual(result['status'], 'unrecognized_response')
                self.assertNotIn('tenant_id', result)

    def test_http_and_network_errors_remain_unknown(self):
        for error in [urllib.error.HTTPError('url', 400, 'Bad request', {}, None),
                      urllib.error.URLError('offline'), ValueError('bad JSON')]:
            with self.subTest(error=type(error).__name__), patch.object(trace, 'fetch_json', side_effect=error):
                result = trace.discover('example.onmicrosoft.com')
                self.assertTrue(result['status'].startswith('unknown'))
                self.assertEqual(result['mailbox_status'], 'not_established')

    def test_redirects_are_blocked(self):
        request = trace.urllib.request.Request('https://login.microsoftonline.com/example/v2.0')
        with self.assertRaises(urllib.error.HTTPError):
            trace.NoRedirect().redirect_request(request, None, 302, 'Found', {}, 'https://evil.example')

    def test_dns_is_explicit_and_not_claimed_as_mailbox(self):
        getter = lambda url: ({'issuer': f'https://login.microsoftonline.com/{TENANT}/v2.0'}, 'hash')
        with patch.object(trace, 'query_dns', return_value={'status': 'raw_response_uninterpreted'}) as dns:
            trace.discover('example.onmicrosoft.com', getter=getter)
            dns.assert_not_called()
            result = trace.discover('example.onmicrosoft.com', include_dns=True, getter=getter)
            self.assertEqual(dns.call_count, 2)
            self.assertEqual(result['mailbox_status'], 'not_established')

    def test_dns_invocation_uses_argument_list_without_shell(self):
        with patch.object(trace.shutil, 'which', return_value='/usr/bin/nslookup'), \
             patch.object(trace.subprocess, 'run') as run:
            run.return_value.stdout = 'no answer'
            run.return_value.stderr = ''
            run.return_value.returncode = 0
            self.assertEqual(trace.query_dns('example.com', 'MX')['status'], 'raw_response_uninterpreted')
            self.assertEqual(run.call_args.args[0], ['/usr/bin/nslookup', '-type=MX', 'example.com'])
            self.assertFalse(run.call_args.kwargs['shell'])


if __name__ == '__main__':
    unittest.main()
