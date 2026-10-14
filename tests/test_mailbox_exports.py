import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('mailbox_exports', Path(__file__).parents[1] / 'scripts/mailbox_exports.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class MailboxExportTests(unittest.TestCase):
    def parse(self, text, encoding='utf-8'):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'sample.txt'
            p.write_text(text, encoding=encoding)
            return module.inspect(p)

    def test_schema_is_not_an_account(self):
        r = self.parse('<entity Name="Mailbox"><EntityId>fictional</EntityId><attributes><attribute PhysicalName="MailboxId"/></attributes></entity>')
        self.assertEqual(r['kind'], 'schema_definition')
        self.assertEqual(r['field_count'], 1)
        self.assertEqual(r['events'], [])

    def test_raw_counts_and_unknown_zone_preserved(self):
        r = self.parse('<Mailbox Owner="Example"><BulkActionItem StartTime="1/2/2021 3:00:00 PM" Class="RestoreAllItems" State="3" TotalCount="2" ProcessedCount="200"/></Mailbox>')
        self.assertEqual(r['events'][0]['claims']['ProcessedCount'], '200')
        self.assertEqual(r['events'][0]['time_zone'], 'unspecified')
        self.assertTrue(any('exceeds' in w for w in r['warnings']))

    def test_forwarding_preserves_conditions(self):
        r = self.parse('<Mailbox><Folder FolderName="Inbox"><Rule Name="Example" StateFlags="Enabled"><Restriction Type="And"><Value>fictional condition</Value></Restriction><Actions><Action Type="OP_FORWARD"><Recipients><Recipient><Property Id="SmtpAddress / 0000000039FE001F"><Value>sample@example.invalid</Value></Property></Recipient></Recipients></Action></Actions></Rule></Folder></Mailbox>')
        self.assertEqual(r['rules'][0]['forward_recipients'], ['sample@example.invalid'])
        self.assertIn('fictional condition', r['rules'][0]['restriction_xml'])
        self.assertIn('current status unknown', r['rules'][0]['interpretation'])

    def test_settings_are_not_message_migration(self):
        r = self.parse('SettingsMigrationTime : 1/2/2016 1:00:00 PM\nWasSettingsMigrationSuccessful : True\nTimeZone : Eastern Standard Time', 'utf-16')
        self.assertEqual(r['kind'], 'legacy_settings')
        self.assertIn('not message migration', r['events'][0]['interpretation'])

    def test_dtd_rejected(self):
        with self.assertRaises(ValueError):
            self.parse('<!DOCTYPE Mailbox [<!ENTITY a "x">]><Mailbox>&a;</Mailbox>')

    def test_unknown_text_not_claimed_as_evidence(self):
        self.assertEqual(self.parse('unrelated data')['kind'], 'unrecognized')

    def test_error_retained_and_output_not_overwritten(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / 'output'
            r = module.run([Path(d) / 'missing'], dest)
            self.assertEqual(r['sources'][0]['kind'], 'error')
            with self.assertRaises(FileExistsError):
                module.run([Path(d) / 'missing'], dest)

    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'source'
            p.write_text('data')
            link = Path(d) / 'link'
            link.symlink_to(p)
            with self.assertRaises(ValueError):
                module.inspect(link)


if __name__ == '__main__':
    unittest.main()
