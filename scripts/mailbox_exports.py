#!/usr/bin/env python3
"""Read selected mailbox exports offline; preserve source claims, never execute them."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET

MAX_BYTES = 10 * 1024 * 1024


def inspect(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError('Input must be a regular non-symlink file')
    with path.open('rb') as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError('Input exceeds 10 MiB')
    text = raw.decode('utf-16' if raw.startswith((b'\xff\xfe', b'\xfe\xff')) else 'utf-8-sig')
    result = {'source_name': path.name, 'sha256': hashlib.sha256(raw).hexdigest(),
              'kind': 'unrecognized', 'warnings': [], 'events': [], 'rules': []}
    if text.lstrip().startswith('<'):
        if re.search(r'<!\s*(DOCTYPE|ENTITY)\b', text, re.I):
            raise ValueError('DTD and entity declarations are not supported')
        root = ET.fromstring(text)
        if root.tag == 'entity' and root.find('attributes') is not None:
            result.update(kind='schema_definition', entity_name=root.get('Name'),
                          field_count=len(root.findall('./attributes/attribute')))
            result['warnings'].append('Schema identifiers are not mailbox or tenant identities; no account records inferred.')
        elif root.tag == 'Mailbox':
            result.update(kind='mailbox_export', owner_claim=root.get('Owner', ''))
            for i, item in enumerate(root.findall('./BulkActionItem')):
                event = {'source_locator': f'/Mailbox/BulkActionItem[{i+1}]',
                         'claims': dict(item.attrib), 'time_zone': 'unspecified',
                         'interpretation': 'exported action record; outcome and unique message count unverified'}
                result['events'].append(event)
                try:
                    if int(item.get('ProcessedCount', '0')) > int(item.get('TotalCount', '0')):
                        result['warnings'].append(f'BulkActionItem[{i+1}]: ProcessedCount exceeds TotalCount; do not treat as unique messages recovered.')
                except ValueError:
                    result['warnings'].append(f'BulkActionItem[{i+1}]: nonnumeric counts retained verbatim.')
            for folder in root.findall('./Folder'):
                for rule in folder.findall('./Rule'):
                    result['rules'].append({
                        'folder': folder.get('FolderName'), 'claims': dict(rule.attrib),
                        'restriction_xml': ET.tostring(rule.find('Restriction'), encoding='unicode')
                            if rule.find('Restriction') is not None else None,
                        'actions_xml': ET.tostring(rule.find('Actions'), encoding='unicode')
                            if rule.find('Actions') is not None else None,
                        'action_types': [a.get('Type') for a in rule.findall('./Actions/Action')],
                        'forward_recipients': [p.findtext('Value') for p in rule.findall('./Actions/Action/Recipients/Recipient/Property')
                                               if (p.get('Id') or '').startswith('SmtpAddress /')],
                        'interpretation': 'snapshot only; conditions retained, not evaluated; current status unknown'})
            result['warnings'].append('Export metadata does not establish a paid subscription, tenant ownership, or current mailbox state.')
    else:
        settings = dict(line.split(' : ', 1) for line in text.splitlines() if ' : ' in line)
        if 'SettingsMigrationTime' in settings:
            result.update(kind='legacy_settings', settings=settings)
            result['events'].append({'source_locator': 'SettingsMigrationTime',
                                     'claims': {'time': settings['SettingsMigrationTime'],
                                                'success_flag': settings.get('WasSettingsMigrationSuccessful')},
                                     'time_zone_claim': settings.get('TimeZone'),
                                     'interpretation': 'settings migration claim only; not message migration or account creation'})
    return result


def run(paths, output):
    if not 1 <= len(paths) <= 100:
        raise ValueError('Provide between 1 and 100 files')
    results = []
    for path in paths:
        try:
            results.append(inspect(path))
        except (OSError, ValueError, ET.ParseError) as exc:
            results.append({'source_name': Path(path).name, 'kind': 'error', 'error': str(exc)})
    report = {'schema_version': 1, 'scope': 'offline source claims; no live service validation',
              'sources': results}
    output = Path(output)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    (output / 'mailbox-review.json').write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf-8')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', action='append', required=True, help='Repeat for each local export')
    parser.add_argument('--output', required=True, help='New private directory outside your repository')
    args = parser.parse_args()
    report = run(args.input, args.output)
    print('Wrote mailbox-review.json; source errors:', sum(s['kind'] == 'error' for s in report['sources']))
    return 1 if any(s['kind'] == 'error' for s in report['sources']) else 0


if __name__ == '__main__':
    raise SystemExit(main())
