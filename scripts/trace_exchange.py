#!/usr/bin/env python3
"""Read-only evidence inventory and opt-in public tenant discovery (Python 3.9+)."""

import argparse
import hashlib
import ipaddress
import json
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from pathlib import Path

MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024
CONSUMER_TENANT = '9188040d-6c67-4c5b-b112-36a304b66dad'
SHARED_DOMAINS = {'hotmail.com', 'outlook.com', 'live.com', 'windowslive.com',
                  'msn.com', 'gmail.com', 'icloud.com', 'me.com', 'mac.com',
                  'yahoo.com', 'onmicrosoft.com'}
EMAIL_RE = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
DOMAIN_RE = re.compile(r'(?<![\w.-])[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.onmicrosoft\.com\b', re.I)
GUID_RE = re.compile(r'(?<![\w-])[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}(?![\w-])', re.I)
BILLING_RE = re.compile(r'\b(invoice|subscription|billing|order number|Exchange Online|Microsoft 365|Office 365|GoDaddy)\b', re.I)
LIMITS = [
    'Identifiers in an artifact are leads, not proof of ownership, aliases, admin role or a mailbox.',
    'Sender domains, quoted examples and third-party tenants can appear in evidence.',
    'File dates are not used to date an account. EML Date headers are unverified claims.',
    'Public discovery describes the observation time only, not historical configuration.',
    'No password, MFA, DNS, account, tenant or mailbox changes are performed.',
    'This tool cannot restore deleted mail or authenticate to a mailbox.',
]


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def normalize_target(value):
    """Accept only an explicit DNS domain or full UUID, never a URL or email."""
    value = value.strip().lower().rstrip('.')
    if re.fullmatch(GUID_RE.pattern, value):
        return str(uuid.UUID(value))
    if len(value) > 253 or '.' not in value:
        raise ValueError('Use a full domain or a canonical tenant UUID.')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError('IP addresses are not tenant domains.')
    if not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
               for label in value.split('.')):
        raise ValueError('Use an ASCII domain only; no email, URL, port or path.')
    if value in SHARED_DOMAINS:
        raise ValueError('A shared email-provider domain cannot identify your business tenant.')
    return value


def sections(raw, suffix):
    if suffix != '.eml':
        # UTF-16 exports are common in Windows; otherwise expect UTF-8 text.
        encoding = 'utf-16' if raw.startswith((b'\xff\xfe', b'\xfe\xff')) else 'utf-8-sig'
        return [('text', raw.decode(encoding, errors='replace'))], None
    message = BytesParser(policy=policy.default).parsebytes(raw)
    parts = [('headers', '\n'.join(f'{key}: {value}' for key, value in message.items()))]
    for number, part in enumerate(message.walk()):
        if part.get_content_type() not in ('text/plain', 'text/html'):
            continue
        if part.get_content_disposition() == 'attachment':
            continue
        payload = part.get_payload(decode=True)
        if isinstance(payload, bytes):
            try:
                text = payload.decode(part.get_content_charset() or 'utf-8', errors='replace')
            except LookupError:
                text = payload.decode('utf-8', errors='replace')
            parts.append((f'decoded-mime-part-{number}', text))
    return parts, str(message.get('Date', '')) or None


def inspect_file(path):
    path = Path(path).expanduser()
    record = {'source_path': str(path.absolute()), 'observed_at_utc': utc_now(),
              'status': 'unread', 'historical_status': 'unverified'}
    try:
        if path.is_symlink() or not path.is_file():
            raise ValueError('Supply a regular file, not a symlink or directory.')
        if path.suffix.lower() not in {'.txt', '.md', '.json', '.csv', '.eml'}:
            raise ValueError('Unsupported format. Supply text, JSON, CSV, Markdown or EML; no PDF/OCR.')
        with path.open('rb') as handle:
            raw = handle.read(MAX_FILE_BYTES + 1)
        if len(raw) > MAX_FILE_BYTES:
            raise ValueError('File exceeds the 10 MiB limit.')
        record.update(sha256=hashlib.sha256(raw).hexdigest(), size_bytes=len(raw))
        chunks, date_claim = sections(raw, path.suffix.lower())
        candidates = []
        billing_lines = []
        for section, text in chunks:
            for line_number, line in enumerate(text.splitlines(), 1):
                for kind, pattern in [('email', EMAIL_RE), ('tenant_domain', DOMAIN_RE),
                                      ('unclassified_guid', GUID_RE)]:
                    for value in sorted(set(m.group().rstrip('.') for m in pattern.finditer(line))):
                        candidates.append({'kind': kind, 'value': value, 'section': section,
                                           'line': line_number, 'status': 'observed_in_artifact_only'})
                if BILLING_RE.search(line):
                    billing_lines.append({'section': section, 'line': line_number})
        record.update(status='inspected', date_header_claim=date_claim,
                      candidates=candidates, billing_keyword_locations=billing_lines)
    except (OSError, ValueError, TypeError, UnicodeError) as exc:
        record.update(status='error', error_type=type(exc).__name__, detail=str(exc))
    return record


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, 'Redirect not followed', headers, fp)


def fetch_json(url):
    # Only URLs built by discover() reach this function. No login or token requests.
    opener = urllib.request.build_opener(NoRedirect())
    request = urllib.request.Request(url, headers={'Accept': 'application/json',
                                                  'User-Agent': 'ExchangeEvidenceTrace/1.0'})
    with opener.open(request, timeout=15) as response:
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ValueError('Discovery response exceeded 1 MiB.')
        document = json.loads(raw)
        if not isinstance(document, dict):
            raise ValueError('Discovery response was not a JSON object.')
        return document, hashlib.sha256(raw).hexdigest()


def tenant_from_issuer(issuer):
    if not isinstance(issuer, str):
        return None
    match = re.fullmatch(r'https://login\.microsoftonline\.com/([0-9a-fA-F-]{36})/v2\.0', issuer)
    if not match or not re.fullmatch(GUID_RE.pattern, match.group(1)):
        return None
    return str(uuid.UUID(match.group(1)))


def query_dns(target, record_type):
    executable = shutil.which('nslookup')
    if not executable:
        return {'status': 'unavailable', 'detail': 'nslookup is not installed.'}
    try:
        result = subprocess.run([executable, f'-type={record_type}', target],
                                capture_output=True, text=True, errors='replace', timeout=15,
                                shell=False)
        # Preserve raw output; localized nslookup text is not a reliable parser contract.
        return {'status': 'raw_response_uninterpreted', 'return_code': result.returncode,
                'stdout': result.stdout[:32768], 'stderr': result.stderr[:4096],
                'observed_at_utc': utc_now()}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'status': 'unknown', 'error_type': type(exc).__name__}


def discover(target, include_dns=False, getter=None):
    target = normalize_target(target)
    url = f'https://login.microsoftonline.com/{target}/v2.0/.well-known/openid-configuration'
    record = {'target': target, 'observed_at_utc': utc_now(), 'url': url,
              'status': 'unknown', 'historical_status': 'not_established',
              'mailbox_status': 'not_established', 'ownership_status': 'not_established'}
    try:
        document, digest = (getter or fetch_json)(url)
        issuer = document.get('issuer')
        tenant_id = tenant_from_issuer(issuer)
        record['response_sha256'] = digest
        if tenant_id == CONSUMER_TENANT:
            record.update(status='shared_consumer_authority', tenant_id=tenant_id)
        elif tenant_id:
            record.update(status='current_tenant_metadata_observed', tenant_id=tenant_id)
        else:
            record.update(status='unrecognized_response')
        # Store validated issuer only, not arbitrary remote body/error text.
        if tenant_id:
            record['issuer'] = issuer
    except urllib.error.HTTPError as exc:
        record.update(status='unknown_http_error', http_status=exc.code)
    except (urllib.error.URLError, OSError, ValueError, TypeError) as exc:
        record.update(status='unknown_request_error', error_type=type(exc).__name__)
    if include_dns and '.' in target:
        record['dns'] = {kind: query_dns(target, kind) for kind in ('MX', 'TXT')}
    return record


def render_summary(report):
    lines = ['# Exchange evidence trace', '', f"Observed: {report['observed_at_utc']}", '',
             '## Local artifact inventory', '']
    for index, artifact in enumerate(report['artifacts'], 1):
        lines.append(f"- File {index}: {artifact['status']}; "
                     f"{len(artifact.get('candidates', []))} identifier occurrences. "
                     'See the local JSON for source locations.')
    lines += ['', '## Explicit public discovery', '']
    for record in report['discovery']:
        lines.append(f"- `{record['target']}`: **{record['status']}**; "
                     f"tenant ID: `{record.get('tenant_id', 'not established')}`.")
    lines += ['', '## Interpretation limits', ''] + ['- ' + item for item in LIMITS]
    lines += ['', 'MX routing is not proof of a mailbox or subscription. A Microsoft TXT token',
              'does not prove completed verification, current ownership or admin access.',
              'An error or missing record does not establish deletion.', '',
              'Reports contain personal identifiers. Keep them local or share privately.', '']
    return '\n'.join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', action='append', default=[], metavar='FILE',
                        help='Explicit local text/EML file; repeat as needed (max 100).')
    parser.add_argument('--domain', action='append', default=[], metavar='DOMAIN_OR_UUID',
                        help='Explicit tenant target; no automatic discovery from file contents.')
    parser.add_argument('--online', action='store_true', help='Allow public Microsoft OIDC GET requests.')
    parser.add_argument('--dns', action='store_true', help='Also query MX/TXT via the system DNS resolver.')
    parser.add_argument('--output', required=True, help='A new local output directory; never overwritten.')
    args = parser.parse_args(argv)
    if not args.evidence and not args.domain:
        parser.error('Provide --evidence or --domain.')
    if len(args.evidence) > 100 or len(args.domain) > 20:
        parser.error('Limit is 100 explicit files and 20 explicit targets per run.')
    if args.domain and not args.online:
        parser.error('--domain requires --online. File inspection alone stays offline.')
    if args.dns and not (args.online and args.domain):
        parser.error('--dns requires --online and --domain.')
    try:
        targets = list(dict.fromkeys(normalize_target(item) for item in args.domain))
    except ValueError as exc:
        parser.error(str(exc))
    output = Path(args.output).expanduser()
    try:
        output.mkdir(mode=0o700, parents=True, exist_ok=False)
    except OSError as exc:
        parser.error(f'Cannot create a new output directory: {exc}')
    report = {'schema_version': 1, 'observed_at_utc': utc_now(), 'limitations': LIMITS,
              'artifacts': [inspect_file(item) for item in args.evidence],
              'discovery': [discover(item, args.dns) for item in targets]}
    with (output / 'trace.json').open('x', encoding='utf-8') as handle:
        json.dump(report, handle, indent=2, ensure_ascii=True)
        handle.write('\n')
    with (output / 'summary.md').open('x', encoding='utf-8') as handle:
        handle.write(render_summary(report))
    incomplete = any(item['status'] == 'error' for item in report['artifacts']) or any(
        item['status'] not in {'current_tenant_metadata_observed', 'shared_consumer_authority'}
        or any(dns['status'] != 'raw_response_uninterpreted' or dns.get('return_code') != 0
               for dns in item.get('dns', {}).values()) for item in report['discovery'])
    print(f"Wrote local reports: {len(report['artifacts'])} file(s), {len(targets)} target(s).")
    print('Incomplete checks: yes. Review trace.json.' if incomplete else
          'Collection finished. Identifiers remain leads; no mailbox access was verified.')
    return 2 if incomplete else 0


if __name__ == '__main__':
    sys.exit(main())
