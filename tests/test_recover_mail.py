"""Tests for scripts/recover_mail.py using only synthetic, fabricated emails.

No real personal data, credentials, or third-party content is used anywhere
in this test suite.
"""
from __future__ import annotations

import csv
import io
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
import zipfile
from email.message import EmailMessage
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import recover_mail as rm  # noqa: E402


def make_simple_eml(
    subject="Hello",
    from_addr="alice@example.test",
    to_addr="bob@example.test",
    body="Hi Bob, this is a test message.",
    message_id="<msg-1@example.test>",
    date="Mon, 01 Jan 2024 12:00:00 +0000",
    cc_addr=None,
):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_addr
    if cc_addr:
        msg["Cc"] = cc_addr
    if message_id is not None:
        msg["Message-ID"] = message_id
    if date is not None:
        msg["Date"] = date
    msg.set_content(body)
    return msg.as_bytes()


def make_multipart_with_attachment(
    subject="Report attached",
    attachment_name="report.txt",
    attachment_bytes=b"attachment payload contents",
    body="See attached file.",
    message_id="<msg-attach@example.test>",
):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = "sender@example.test"
    msg["To"] = "receiver@example.test"
    msg["Message-ID"] = message_id
    msg["Date"] = "Tue, 02 Jan 2024 08:30:00 +0000"
    msg.set_content(body)
    msg.add_attachment(
        attachment_bytes,
        maintype="text",
        subtype="plain",
        filename=attachment_name,
    )
    return msg.as_bytes()


def make_unicode_header_eml():
    msg = EmailMessage()
    msg["Subject"] = "R\u00e9sum\u00e9 \u2014 \u65e5\u672c\u8a9e \U0001F600"
    msg["From"] = "\u00c9lodie Dupont <elodie@example.test>"
    msg["To"] = "\u5f20\u4e09 <zhang@example.test>"
    msg["Message-ID"] = "<unicode-1@example.test>"
    msg["Date"] = "Wed, 03 Jan 2024 09:00:00 +0000"
    msg.set_content("Contenu avec caract\u00e8res accentu\u00e9s et \u65e5\u672c\u8a9e.")
    return msg.as_bytes()


def make_manifest(entries):
    return json.dumps({"messages": entries}).encode("utf-8")


class SanitizeAndSafetyTests(unittest.TestCase):
    def test_sanitize_filename_strips_path_components(self):
        self.assertEqual(rm.sanitize_filename("../../etc/passwd"), "passwd")
        self.assertEqual(rm.sanitize_filename("..\\..\\windows\\win.ini"), "win.ini")

    def test_sanitize_filename_handles_empty(self):
        self.assertEqual(rm.sanitize_filename(""), "unnamed")
        self.assertEqual(rm.sanitize_filename(None), "unnamed")

    def test_unsafe_zip_member_detection(self):
        self.assertEqual(rm.is_unsafe_zip_member_name("/etc/passwd"), "absolute-path")
        self.assertEqual(rm.is_unsafe_zip_member_name("C:\\evil.eml"), "absolute-path")
        self.assertEqual(rm.is_unsafe_zip_member_name("../../escape.eml"), "path-traversal")
        self.assertEqual(rm.is_unsafe_zip_member_name("a/../../b.eml"), "path-traversal")
        self.assertIsNone(rm.is_unsafe_zip_member_name("normal/dir/file.eml"))


class RecoverMailIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="recover_mail_test_")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.input_dir = Path(self.tmpdir) / "input"
        self.output_dir = Path(self.tmpdir) / "output"
        self.input_dir.mkdir()

    def make_zip(self, files: dict, name="archive.zip") -> Path:
        zip_path = Path(self.tmpdir) / name
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for arcname, data in files.items():
                zf.writestr(arcname, data)
        return zip_path

    def default_limits(self):
        return rm.Limits(
            max_members=rm.DEFAULT_MAX_MEMBERS,
            max_total_size=rm.DEFAULT_MAX_TOTAL_UNCOMPRESSED,
            max_file_size=rm.DEFAULT_MAX_FILE_SIZE,
            max_compression_ratio=rm.DEFAULT_MAX_COMPRESSION_RATIO,
        )

    def read_messages_csv(self):
        with open(self.output_dir / "messages.csv", newline="", encoding="utf-8") as fh:
            return list(csv.DictReader(fh))

    def read_attachments_csv(self):
        with open(self.output_dir / "attachments.csv", newline="", encoding="utf-8") as fh:
            return list(csv.DictReader(fh))

    # ------------------------------------------------------------------
    def test_multipart_with_attachment(self):
        zpath = self.make_zip({"mail/report.eml": make_multipart_with_attachment()})
        summary = rm.run(zpath, self.output_dir, self.default_limits())

        self.assertEqual(summary["unique_messages"], 1)
        self.assertEqual(summary["total_attachments"], 1)

        rows = self.read_messages_csv()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["subject"], "Report attached")
        self.assertEqual(int(rows[0]["attachment_count"]), 1)

        att_rows = self.read_attachments_csv()
        self.assertEqual(len(att_rows), 1)
        self.assertEqual(att_rows[0]["original_filename"], "report.txt")
        saved_path = self.output_dir / att_rows[0]["saved_relative_path"]
        self.assertTrue(saved_path.is_file())
        self.assertEqual(saved_path.read_bytes(), b"attachment payload contents")

        # Original source zip must remain untouched.
        with zipfile.ZipFile(zpath) as zf:
            self.assertIn("mail/report.eml", zf.namelist())

    def test_unicode_and_encoded_headers(self):
        zpath = self.make_zip({"mail/unicode.eml": make_unicode_header_eml()})
        rm.run(zpath, self.output_dir, self.default_limits())

        rows = self.read_messages_csv()
        self.assertEqual(len(rows), 1)
        self.assertIn("\u65e5\u672c\u8a9e", rows[0]["subject"])
        self.assertIn("\u00c9lodie", rows[0]["from"])
        self.assertIn("\u5f20\u4e09", rows[0]["to"])

    def test_duplicate_messages_different_source_filenames(self):
        data = make_simple_eml(subject="Same content")
        zpath = self.make_zip({
            "mail/copy-a.eml": data,
            "backup/copy-b.eml": data,
        })
        summary = rm.run(zpath, self.output_dir, self.default_limits())

        self.assertEqual(summary["unique_messages"], 1)
        self.assertEqual(summary["duplicate_message_count"], 1)

        rows = self.read_messages_csv()
        self.assertEqual(len(rows), 1)
        sources = rows[0]["source_paths"].split(";")
        self.assertIn("mail/copy-a.eml", sources)
        self.assertIn("backup/copy-b.eml", sources)

    def test_same_message_id_different_content_are_not_merged(self):
        shared_id = "<same-id@example.test>"
        data_a = make_simple_eml(subject="Version A", message_id=shared_id, body="Body A")
        data_b = make_simple_eml(subject="Version B", message_id=shared_id, body="Body B")
        zpath = self.make_zip({"mail/a.eml": data_a, "mail/b.eml": data_b})
        summary = rm.run(zpath, self.output_dir, self.default_limits())

        self.assertEqual(summary["unique_messages"], 2)
        rows = self.read_messages_csv()
        subjects = sorted(r["subject"] for r in rows)
        self.assertEqual(subjects, ["Version A", "Version B"])
        message_ids = {r["message_id"] for r in rows}
        self.assertEqual(message_ids, {shared_id})
        # Two distinct saved message files must exist.
        shas = {r["sha256"] for r in rows}
        self.assertEqual(len(shas), 2)

    def test_two_attachments_same_filename_different_contents(self):
        eml_a = make_multipart_with_attachment(
            attachment_name="data.txt", attachment_bytes=b"payload one",
            message_id="<att-a@example.test>",
        )
        eml_b = make_multipart_with_attachment(
            attachment_name="data.txt", attachment_bytes=b"payload two - different",
            message_id="<att-b@example.test>",
        )
        zpath = self.make_zip({"mail/a.eml": eml_a, "mail/b.eml": eml_b})
        summary = rm.run(zpath, self.output_dir, self.default_limits())

        self.assertEqual(summary["total_attachments"], 2)
        att_rows = self.read_attachments_csv()
        saved_paths = {r["saved_relative_path"] for r in att_rows}
        self.assertEqual(len(saved_paths), 2)  # no filename collision/overwrite
        contents = set()
        for r in att_rows:
            contents.add((self.output_dir / r["saved_relative_path"]).read_bytes())
        self.assertEqual(contents, {b"payload one", b"payload two - different"})

    def test_malformed_mime_and_missing_headers_do_not_crash(self):
        malformed = (
            b"From: broken@example.test\r\n"
            b"Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n"
            b"\r\n"
            b"--BOUND\r\n"
            b"Content-Type: text/plain\r\n"
            b"\r\n"
            b"Body text with no closing boundary and no Date/To headers.\r\n"
        )
        well_formed = make_simple_eml(subject="Fine", to_addr=None or "someone@example.test")
        no_headers = b"This is not really a valid email at all, just bytes.\r\n"

        zpath = self.make_zip({
            "mail/malformed.eml": malformed,
            "mail/fine.eml": well_formed,
            "mail/noheaders.eml": no_headers,
        })
        summary = rm.run(zpath, self.output_dir, self.default_limits())

        self.assertEqual(summary["unique_messages"], 3)
        self.assertGreaterEqual(summary["messages_marked_partial"], 2)
        rows = {r["sha256"]: r for r in self.read_messages_csv()}
        self.assertEqual(len(rows), 3)
        # None should have crashed the run or been silently dropped.
        completeness_values = {r["completeness"] for r in rows.values()}
        self.assertIn("partial", completeness_values)

    def test_zip_traversal_and_oversized_members_are_rejected(self):
        good = make_simple_eml(subject="Legit message")
        zip_path = Path(self.tmpdir) / "malicious.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("good/mail.eml", good)
            zf.writestr("../escape.eml", make_simple_eml(subject="Traversal"))
            zf.writestr("/absolute.eml", make_simple_eml(subject="Absolute"))
            oversized = b"A" * 2048
            zf.writestr("mail/huge.eml", oversized)

        limits = rm.Limits(
            max_members=rm.DEFAULT_MAX_MEMBERS,
            max_total_size=rm.DEFAULT_MAX_TOTAL_UNCOMPRESSED,
            max_file_size=1024,  # smaller than the oversized member
            max_compression_ratio=rm.DEFAULT_MAX_COMPRESSION_RATIO,
        )
        summary = rm.run(zip_path, self.output_dir, limits)

        self.assertEqual(summary["unique_messages"], 1)  # only the legit message survives
        reasons = {e["reason"] for e in summary["safety_events"]}
        self.assertIn("path-traversal", reasons)
        self.assertIn("absolute-path", reasons)
        self.assertIn("file-size-limit-exceeded", reasons)
        # Nothing must have been written outside the output directory.
        escape_target = self.output_dir.parent / "escape.eml"
        self.assertFalse(escape_target.exists())

    def test_zip_bomb_compression_ratio_rejected(self):
        zip_path = Path(self.tmpdir) / "bomb.zip"
        # A highly compressible, large payload gives a large expansion ratio.
        payload = b"0" * (5 * 1024 * 1024)
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("mail/bomb.eml", payload)
            zf.writestr("mail/normal.eml", make_simple_eml(subject="Normal"))

        limits = rm.Limits(
            max_members=rm.DEFAULT_MAX_MEMBERS,
            max_total_size=rm.DEFAULT_MAX_TOTAL_UNCOMPRESSED,
            max_file_size=rm.DEFAULT_MAX_FILE_SIZE,
            max_compression_ratio=10.0,
        )
        summary = rm.run(zip_path, self.output_dir, limits)
        reasons = {e["reason"] for e in summary["safety_events"]}
        self.assertIn("compression-ratio-limit-exceeded", reasons)
        self.assertEqual(summary["unique_messages"], 1)

    def test_manifest_hash_mismatch_is_reported(self):
        data = make_simple_eml(subject="Manifest checked")
        wrong_hash = "0" * 64
        manifest = make_manifest([
            {"archive_path": "mail/checked.eml", "sha256": wrong_hash},
        ])
        zpath = self.make_zip({
            "mail/checked.eml": data,
            "manifest.json": manifest,
        })
        summary = rm.run(zpath, self.output_dir, self.default_limits())

        hv = summary["hash_verification"]
        self.assertTrue(hv["manifest_present"])
        self.assertEqual(hv["mismatched"], 1)
        self.assertEqual(hv["matched"], 0)
        self.assertIn("mail/checked.eml", hv["mismatch_details"])

        rows = self.read_messages_csv()
        self.assertEqual(rows[0]["manifest_status"], "mismatched")

    def test_manifest_hash_match_is_reported(self):
        data = make_simple_eml(subject="Manifest verified ok")
        correct_hash = rm.sha256_hex(data)
        manifest = make_manifest([
            {"archive_path": "mail/ok.eml", "sha256": correct_hash},
        ])
        zpath = self.make_zip({"mail/ok.eml": data, "manifest.json": manifest})
        summary = rm.run(zpath, self.output_dir, self.default_limits())

        hv = summary["hash_verification"]
        self.assertEqual(hv["matched"], 1)
        self.assertEqual(hv["mismatched"], 0)
        rows = self.read_messages_csv()
        self.assertEqual(rows[0]["manifest_status"], "matched")

    def test_idempotent_rerun_produces_stable_outputs(self):
        zpath = self.make_zip({
            "mail/one.eml": make_simple_eml(subject="First"),
            "mail/two.eml": make_multipart_with_attachment(),
        })
        limits = self.default_limits()
        summary1 = rm.run(zpath, self.output_dir, limits)
        messages_before = sorted((self.output_dir / "messages").iterdir())
        attachments_before = sorted((self.output_dir / "attachments").iterdir())
        contents_before = {p: p.read_bytes() for p in messages_before + attachments_before}

        summary2 = rm.run(zpath, self.output_dir, limits)
        messages_after = sorted((self.output_dir / "messages").iterdir())
        attachments_after = sorted((self.output_dir / "attachments").iterdir())

        self.assertEqual(messages_before, messages_after)
        self.assertEqual(attachments_before, attachments_after)
        for p in messages_after + attachments_after:
            self.assertEqual(contents_before[p], p.read_bytes())

        self.assertEqual(summary1["unique_messages"], summary2["unique_messages"])
        self.assertEqual(summary1["total_attachments"], summary2["total_attachments"])

    def test_directory_input_is_supported(self):
        (self.input_dir / "one.eml").write_bytes(make_simple_eml(subject="Dir message"))
        sub = self.input_dir / "nested"
        sub.mkdir()
        (sub / "two.eml").write_bytes(make_multipart_with_attachment())

        summary = rm.run(self.input_dir, self.output_dir, self.default_limits())
        self.assertEqual(summary["unique_messages"], 2)
        self.assertEqual(summary["total_attachments"], 1)

    def test_sqlite_index_is_searchable(self):
        zpath = self.make_zip({"mail/one.eml": make_simple_eml(subject="Findable subject xyz")})
        rm.run(zpath, self.output_dir, self.default_limits())

        conn = sqlite3.connect(str(self.output_dir / "recovery.sqlite"))
        try:
            cur = conn.execute("SELECT subject FROM messages WHERE subject LIKE '%xyz%'")
            rows = cur.fetchall()
            self.assertEqual(len(rows), 1)
        finally:
            conn.close()

    def test_summary_json_written_and_console_has_no_body_text(self):
        zpath = self.make_zip({"mail/one.eml": make_simple_eml(subject="Secretive body content")})
        summary = rm.run(zpath, self.output_dir, self.default_limits())
        summary_path = self.output_dir / "summary.json"
        self.assertTrue(summary_path.is_file())
        on_disk = json.loads(summary_path.read_text(encoding="utf-8"))
        self.assertEqual(on_disk["unique_messages"], 1)

        buf = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = buf
        try:
            rm.print_console_summary(summary)
        finally:
            sys.stdout = old_stdout
        console_text = buf.getvalue()
        self.assertNotIn("Hi Bob", console_text)
        self.assertIn("Unique messages", console_text)

    def test_cli_main_end_to_end(self):
        zpath = self.make_zip({"mail/one.eml": make_simple_eml(subject="CLI run")})
        rc = rm.main(["--input", str(zpath), "--output", str(self.output_dir)])
        self.assertEqual(rc, 0)
        self.assertTrue((self.output_dir / "messages.csv").is_file())
        self.assertTrue((self.output_dir / "attachments.csv").is_file())
        self.assertTrue((self.output_dir / "recovery.sqlite").is_file())
        self.assertTrue((self.output_dir / "summary.json").is_file())

    def test_input_files_are_never_modified(self):
        original = make_simple_eml(subject="Untouched")
        zpath = self.make_zip({"mail/one.eml": original})
        before_bytes = zpath.read_bytes()
        rm.run(zpath, self.output_dir, self.default_limits())
        after_bytes = zpath.read_bytes()
        self.assertEqual(before_bytes, after_bytes)


if __name__ == "__main__":
    unittest.main()
