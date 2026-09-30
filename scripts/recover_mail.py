#!/usr/bin/env python3
"""Offline email recovery tool.

Processes an existing ZIP archive of recovered ``.eml`` messages (or a
directory containing ``.eml`` files), preserves the original message
bytes, extracts attachments, and produces a searchable local index.

The tool never contacts a network, never signs in to any service, and
never executes attachments or renders remote content. Everything is
computed from the standard library only.

Usage:
    python3 scripts/recover_mail.py \\
        --input /path/to/recovered-icloud-mail.zip \\
        --output /path/to/local-recovery-results

See README.md for a full description of the outputs and safety limits.
"""
from __future__ import annotations

import argparse
import csv
import dataclasses
import email
import email.header
import email.policy
import email.utils
import hashlib
import json
import os
import re
import sqlite3
import stat
import sys
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Safety limits (overridable via CLI flags). These exist to defend against
# zip bombs / path traversal / resource exhaustion when processing archives
# recovered from unknown or untrusted sources.
# ---------------------------------------------------------------------------
DEFAULT_MAX_MEMBERS = 200_000
DEFAULT_MAX_TOTAL_UNCOMPRESSED = 5 * 1024 ** 3  # 5 GiB
DEFAULT_MAX_FILE_SIZE = 200 * 1024 ** 2  # 200 MiB
DEFAULT_MAX_COMPRESSION_RATIO = 100.0

EML_SUFFIX = ".eml"
MANIFEST_NAME = "manifest.json"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------
@dataclasses.dataclass
class SourceFile:
    """A single .eml file discovered in the input, before deduplication."""

    data: bytes
    source_path: str  # human readable location (zip member or file path)


@dataclasses.dataclass
class ManifestEntry:
    archive_path: str
    sha256: str


@dataclasses.dataclass
class SafetyEvent:
    member: str
    reason: str


@dataclasses.dataclass
class UniqueMessage:
    sha256: str
    data: bytes
    source_paths: List[str] = dataclasses.field(default_factory=list)
    manifest_status: str = "not-listed"  # matched | mismatched | not-listed


# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------
def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sanitize_filename(name: Optional[str]) -> str:
    """Return a filesystem-safe, non-empty basename with no path parts."""
    if not name:
        name = "unnamed"
    # Drop any directory components an attacker/broken client may have
    # embedded in the filename header.
    name = name.replace("\\", "/").split("/")[-1]
    name = name.strip().strip(".")
    name = re.sub(r"[^A-Za-z0-9._ -]", "_", name)
    name = name.strip()
    if not name:
        name = "unnamed"
    # Guard against reserved/hidden names and excessive length.
    if name in (".", ".."):
        name = "unnamed"
    return name[:150]


def is_unsafe_zip_member_name(name: str) -> Optional[str]:
    """Return a reason string if a zip member name is unsafe, else None."""
    if not name or name.endswith("/"):
        return None  # directory entries are handled separately
    normalized = name.replace("\\", "/")
    if normalized.startswith("/"):
        return "absolute-path"
    if re.match(r"^[A-Za-z]:", normalized):
        return "absolute-path"
    parts = normalized.split("/")
    if any(p == ".." for p in parts):
        return "path-traversal"
    if any(p == "" for p in parts[:-1]):
        # Empty path segment other than at the very end (e.g. "a//b") is odd
        # but not unsafe by itself; only reject true traversal/absolute forms.
        pass
    return None


def is_symlink_member(info: "zipfile.ZipInfo") -> bool:
    mode = (info.external_attr >> 16) & 0xFFFF
    return bool(mode) and stat.S_ISLNK(mode)


# ---------------------------------------------------------------------------
# Input gathering
# ---------------------------------------------------------------------------
class Limits:
    def __init__(self, max_members: int, max_total_size: int, max_file_size: int,
                 max_compression_ratio: float):
        self.max_members = max_members
        self.max_total_size = max_total_size
        self.max_file_size = max_file_size
        self.max_compression_ratio = max_compression_ratio


def parse_manifest(raw: bytes) -> List[ManifestEntry]:
    entries: List[ManifestEntry] = []
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return entries
    if isinstance(payload, dict):
        records = payload.get("messages") or payload.get("files") or payload.get("entries") or []
    elif isinstance(payload, list):
        records = payload
    else:
        records = []
    for rec in records:
        if not isinstance(rec, dict):
            continue
        path = rec.get("archive_path")
        digest = rec.get("sha256")
        if path and digest:
            entries.append(ManifestEntry(archive_path=str(path), sha256=str(digest).lower()))
    return entries


def gather_from_zip(zip_path: Path, limits: Limits) -> Tuple[List[SourceFile], List[ManifestEntry], List[SafetyEvent], int]:
    """Safely read .eml members from a zip file.

    Returns (source_files, manifest_entries, safety_events, total_members_seen)
    """
    sources: List[SourceFile] = []
    manifest_entries: List[ManifestEntry] = []
    safety_events: List[SafetyEvent] = []
    total_uncompressed = 0
    members_seen = 0

    with zipfile.ZipFile(zip_path) as zf:
        infos = zf.infolist()
        for info in infos:
            members_seen += 1
            if members_seen > limits.max_members:
                safety_events.append(SafetyEvent(info.filename, "member-count-limit-exceeded"))
                break

            name = info.filename
            if name.endswith("/"):
                continue  # directory entry

            unsafe_reason = is_unsafe_zip_member_name(name)
            if unsafe_reason:
                safety_events.append(SafetyEvent(name, unsafe_reason))
                continue
            if is_symlink_member(info):
                safety_events.append(SafetyEvent(name, "symlink-rejected"))
                continue

            if info.file_size > limits.max_file_size:
                safety_events.append(SafetyEvent(name, "file-size-limit-exceeded"))
                continue

            ratio = info.file_size / max(info.compress_size, 1)
            if info.file_size > 0 and ratio > limits.max_compression_ratio:
                safety_events.append(SafetyEvent(name, "compression-ratio-limit-exceeded"))
                continue

            if total_uncompressed + info.file_size > limits.max_total_size:
                safety_events.append(SafetyEvent(name, "total-size-limit-exceeded"))
                break

            base = os.path.basename(name)
            if base == MANIFEST_NAME:
                try:
                    raw = zf.read(info)
                except (zipfile.BadZipFile, OSError) as exc:
                    safety_events.append(SafetyEvent(name, f"manifest-read-error:{exc}"))
                    continue
                total_uncompressed += info.file_size
                manifest_entries.extend(parse_manifest(raw))
                continue

            if not name.lower().endswith(EML_SUFFIX):
                continue  # ignore unrelated files

            try:
                data = zf.read(info)
            except (zipfile.BadZipFile, OSError) as exc:
                safety_events.append(SafetyEvent(name, f"read-error:{exc}"))
                continue
            total_uncompressed += info.file_size
            sources.append(SourceFile(data=data, source_path=name))

    return sources, manifest_entries, safety_events, members_seen


def gather_from_dir(dir_path: Path, limits: Limits) -> Tuple[List[SourceFile], List[ManifestEntry], List[SafetyEvent]]:
    sources: List[SourceFile] = []
    manifest_entries: List[ManifestEntry] = []
    safety_events: List[SafetyEvent] = []
    count = 0
    manifest_path = dir_path / MANIFEST_NAME
    if manifest_path.is_file():
        try:
            manifest_entries.extend(parse_manifest(manifest_path.read_bytes()))
        except OSError:
            pass

    for path in sorted(dir_path.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() != EML_SUFFIX:
            continue
        if path.is_symlink():
            safety_events.append(SafetyEvent(str(path), "symlink-rejected"))
            continue
        count += 1
        if count > limits.max_members:
            safety_events.append(SafetyEvent(str(path), "member-count-limit-exceeded"))
            break
        size = path.stat().st_size
        if size > limits.max_file_size:
            safety_events.append(SafetyEvent(str(path), "file-size-limit-exceeded"))
            continue
        rel = str(path.relative_to(dir_path))
        sources.append(SourceFile(data=path.read_bytes(), source_path=rel))
    return sources, manifest_entries, safety_events


# ---------------------------------------------------------------------------
# Deduplication + manifest verification
# ---------------------------------------------------------------------------
def deduplicate(sources: List[SourceFile], manifest_entries: List[ManifestEntry]) -> Tuple[Dict[str, UniqueMessage], Dict[str, str]]:
    by_hash: Dict[str, UniqueMessage] = {}
    for src in sources:
        digest = sha256_hex(src.data)
        entry = by_hash.get(digest)
        if entry is None:
            entry = UniqueMessage(sha256=digest, data=src.data)
            by_hash[digest] = entry
        entry.source_paths.append(src.source_path)

    manifest_by_path = {m.archive_path: m.sha256 for m in manifest_entries}
    mismatches: Dict[str, str] = {}  # archive_path -> reason

    # index unique messages by any of their source paths for manifest lookup
    path_to_hash: Dict[str, str] = {}
    for digest, msg in by_hash.items():
        for p in msg.source_paths:
            path_to_hash[p] = digest
            # also allow matching by basename, since manifests sometimes use
            # a slightly different relative root than the zip member name.
            path_to_hash.setdefault(os.path.basename(p), digest)

    for archive_path, expected_sha in manifest_by_path.items():
        actual_hash = path_to_hash.get(archive_path) or path_to_hash.get(os.path.basename(archive_path))
        if actual_hash is None:
            mismatches[archive_path] = "listed-file-not-found"
            continue
        if actual_hash.lower() == expected_sha.lower():
            by_hash[actual_hash].manifest_status = "matched"
        else:
            by_hash[actual_hash].manifest_status = "mismatched"
            mismatches[archive_path] = "sha256-mismatch"

    return by_hash, mismatches


# ---------------------------------------------------------------------------
# Message parsing
# ---------------------------------------------------------------------------
def parse_eml(data: bytes) -> Tuple[Optional[email.message.Message], List[str], bool]:
    """Parse raw bytes into an email.message.Message.

    Returns (message_or_none, warnings, used_fallback_parser)
    """
    warnings: List[str] = []
    try:
        msg = email.message_from_bytes(data, policy=email.policy.default)
        for defect in getattr(msg, "defects", []) or []:
            warnings.append(f"defect:{type(defect).__name__}")
        for part in msg.walk():
            for defect in getattr(part, "defects", []) or []:
                warnings.append(f"defect:{type(defect).__name__}")
        return msg, warnings, False
    except Exception as exc:  # pragma: no cover - policy.default is very tolerant
        warnings.append(f"default-policy-parse-error:{exc}")
    try:
        msg = email.message_from_bytes(data, policy=email.policy.compat32)
        warnings.append("used-compat32-fallback-parser")
        return msg, warnings, True
    except Exception as exc:
        warnings.append(f"parse-failed:{exc}")
        return None, warnings, True


def header_str(msg: email.message.Message, name: str) -> str:
    try:
        value = msg.get(name)
    except Exception:
        value = None
    if value is None:
        return ""
    try:
        text = str(value)
    except Exception:
        text = ""
    if "=?" in text and "?=" in text:
        # Looks like an undecoded RFC 2047 encoded word (compat32 fallback
        # path); decode it manually.
        try:
            text = str(email.header.make_header(email.header.decode_header(text)))
        except Exception:
            pass
    return text


def assess_completeness(raw: bytes, msg: Optional[email.message.Message]) -> Tuple[str, List[str]]:
    reasons: List[str] = []
    if msg is None:
        return "partial", ["unparseable"]

    if not header_str(msg, "from").strip():
        reasons.append("missing-from-header")
    if not header_str(msg, "date").strip():
        reasons.append("missing-date-header")

    date_raw = header_str(msg, "date")
    if date_raw:
        try:
            if email.utils.parsedate_to_datetime(date_raw) is None:
                reasons.append("unparseable-date")
        except Exception:
            reasons.append("unparseable-date")

    if msg.is_multipart():
        boundary = msg.get_boundary()
        if not boundary:
            reasons.append("multipart-missing-boundary-parameter")
        else:
            terminator = f"--{boundary}--".encode("ascii", "ignore")
            if terminator not in raw:
                reasons.append("multipart-missing-closing-boundary")

    if b"\r\n\r\n" not in raw and b"\n\n" not in raw:
        reasons.append("no-header-body-separator-found")

    for defect in getattr(msg, "defects", []) or []:
        reasons.append(f"defect:{type(defect).__name__}")

    status = "partial" if reasons else "complete"
    return status, reasons


def is_attachment_part(part: email.message.Message) -> bool:
    if part.is_multipart():
        return False
    try:
        disposition = part.get_content_disposition()
    except Exception:
        disposition = None
    try:
        filename = part.get_filename()
    except Exception:
        filename = None
    try:
        ctype = part.get_content_type()
    except Exception:
        ctype = "application/octet-stream"

    if disposition == "attachment":
        return True
    if filename:
        return True
    if disposition == "inline" and ctype not in ("text/plain", "text/html"):
        return True
    return False


HTML_TAG_RE = re.compile(rb"<[^>]+>")


def decode_text_payload(part: email.message.Message) -> str:
    try:
        payload = part.get_payload(decode=True)
    except Exception:
        payload = None
    if payload is None:
        raw = part.get_payload()
        payload = raw.encode("utf-8", "replace") if isinstance(raw, str) else b""
    charset = None
    try:
        charset = part.get_content_charset()
    except Exception:
        pass
    charset = charset or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except (LookupError, UnicodeDecodeError):
        return payload.decode("utf-8", errors="replace")


def extract_body_text(msg: email.message.Message) -> str:
    """Best-effort plain-text body extraction for indexing only.

    HTML is never rendered or executed: tags are stripped with a regex
    purely so the surrounding text can be searched.
    """
    html_fallback = None
    if msg.is_multipart():
        for part in msg.walk():
            if is_attachment_part(part) or part.is_multipart():
                continue
            ctype = part.get_content_type()
            if ctype == "text/plain":
                return decode_text_payload(part)
            if ctype == "text/html" and html_fallback is None:
                html_fallback = part
    else:
        if not is_attachment_part(msg):
            ctype = msg.get_content_type()
            if ctype == "text/plain":
                return decode_text_payload(msg)
            if ctype == "text/html":
                html_fallback = msg

    if html_fallback is not None:
        text_bytes = decode_text_payload(html_fallback).encode("utf-8", "replace")
        stripped = HTML_TAG_RE.sub(b" ", text_bytes)
        return "[html-only] " + stripped.decode("utf-8", "replace")
    return ""


@dataclasses.dataclass
class AttachmentRecord:
    message_sha256: str
    original_filename: str
    sanitized_filename: str
    saved_relative_path: str
    content_type: str
    size_bytes: int
    sha256: str


def extract_attachments(msg: email.message.Message) -> List[Tuple[bytes, str, str]]:
    """Return list of (data, original_filename, content_type) for attachments."""
    results: List[Tuple[bytes, str, str]] = []
    parts = list(msg.walk()) if msg.is_multipart() else [msg]
    for part in parts:
        if not is_attachment_part(part):
            continue
        try:
            payload = part.get_payload(decode=True)
        except Exception:
            payload = None
        if payload is None:
            raw = part.get_payload()
            payload = raw.encode("utf-8", "replace") if isinstance(raw, str) else b""
        original_name = None
        try:
            original_name = part.get_filename()
        except Exception:
            original_name = None
        if not original_name:
            original_name = "unnamed-attachment"
        try:
            ctype = part.get_content_type()
        except Exception:
            ctype = "application/octet-stream"
        results.append((payload, original_name, ctype))
    return results


# ---------------------------------------------------------------------------
# Output writing
# ---------------------------------------------------------------------------
@dataclasses.dataclass
class MessageRecord:
    sha256: str
    date: str
    from_: str
    to: str
    cc: str
    subject: str
    message_id: str
    source_paths: str
    attachment_count: int
    parsing_warnings: str
    completeness: str
    saved_message_path: str
    manifest_status: str
    body_text: str


def ensure_within_output(output_dir: Path, candidate: Path) -> Path:
    resolved = candidate.resolve()
    if os.path.commonpath([str(resolved), str(output_dir.resolve())]) != str(output_dir.resolve()):
        raise ValueError(f"refusing to write outside output directory: {candidate}")
    return resolved


def write_message_copy(output_dir: Path, unique: UniqueMessage) -> str:
    messages_dir = output_dir / "messages"
    messages_dir.mkdir(parents=True, exist_ok=True)
    target = messages_dir / f"{unique.sha256}.eml"
    ensure_within_output(output_dir, target)
    if target.exists():
        # Idempotent rerun: filename is content-addressed, so an existing
        # file with this name is guaranteed (by construction) to already
        # hold these exact bytes. Verify defensively before trusting that.
        existing = target.read_bytes()
        if sha256_hex(existing) != unique.sha256:
            raise RuntimeError(f"unexpected content collision writing {target}")
    else:
        target.write_bytes(unique.data)
    return str(target.relative_to(output_dir))


def write_attachment(output_dir: Path, message_sha: str, data: bytes, original_name: str) -> Tuple[str, str]:
    attachments_dir = output_dir / "attachments"
    attachments_dir.mkdir(parents=True, exist_ok=True)
    digest = sha256_hex(data)
    sanitized = sanitize_filename(original_name)
    saved_name = f"{digest[:16]}__{sanitized}"
    target = attachments_dir / saved_name
    ensure_within_output(output_dir, target)
    if target.exists():
        existing = target.read_bytes()
        if sha256_hex(existing) != digest:
            raise RuntimeError(f"unexpected content collision writing {target}")
    else:
        target.write_bytes(data)
    return str(target.relative_to(output_dir)), digest


def build_sqlite(output_dir: Path, message_records: List[MessageRecord], attachment_records: List[AttachmentRecord]) -> bool:
    db_path = output_dir / "recovery.sqlite"
    if db_path.exists():
        db_path.unlink()
    conn = sqlite3.connect(str(db_path))
    fts_available = True
    try:
        conn.executescript(
            """
            CREATE TABLE messages (
                sha256 TEXT PRIMARY KEY,
                date TEXT,
                sender TEXT,
                recipients_to TEXT,
                recipients_cc TEXT,
                subject TEXT,
                message_id TEXT,
                source_paths TEXT,
                attachment_count INTEGER,
                parsing_warnings TEXT,
                completeness TEXT,
                saved_message_path TEXT,
                manifest_status TEXT,
                body_text TEXT
            );
            CREATE TABLE attachments (
                message_sha256 TEXT,
                original_filename TEXT,
                sanitized_filename TEXT,
                saved_relative_path TEXT,
                content_type TEXT,
                size_bytes INTEGER,
                sha256 TEXT
            );
            """
        )
        try:
            conn.executescript(
                """
                CREATE VIRTUAL TABLE messages_fts USING fts5(
                    subject, sender, recipients_to, recipients_cc, body_text,
                    content='messages', content_rowid='rowid'
                );
                """
            )
        except sqlite3.OperationalError:
            fts_available = False

        conn.executemany(
            """INSERT INTO messages
               (sha256, date, sender, recipients_to, recipients_cc, subject, message_id,
                source_paths, attachment_count, parsing_warnings, completeness,
                saved_message_path, manifest_status, body_text)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            [
                (
                    m.sha256, m.date, m.from_, m.to, m.cc, m.subject, m.message_id,
                    m.source_paths, m.attachment_count, m.parsing_warnings, m.completeness,
                    m.saved_message_path, m.manifest_status, m.body_text,
                )
                for m in message_records
            ],
        )
        conn.executemany(
            """INSERT INTO attachments
               (message_sha256, original_filename, sanitized_filename, saved_relative_path,
                content_type, size_bytes, sha256)
               VALUES (?,?,?,?,?,?,?)""",
            [
                (
                    a.message_sha256, a.original_filename, a.sanitized_filename,
                    a.saved_relative_path, a.content_type, a.size_bytes, a.sha256,
                )
                for a in attachment_records
            ],
        )
        if fts_available:
            conn.execute(
                """INSERT INTO messages_fts(rowid, subject, sender, recipients_to, recipients_cc, body_text)
                   SELECT rowid, subject, sender, recipients_to, recipients_cc, body_text FROM messages"""
            )
        conn.commit()
    finally:
        conn.close()
    return fts_available


def write_messages_csv(output_dir: Path, records: List[MessageRecord]) -> None:
    path = output_dir / "messages.csv"
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow([
            "sha256", "date", "from", "to", "cc", "subject", "message_id",
            "source_paths", "sha256_dup", "attachment_count", "parsing_warnings",
            "completeness", "saved_message_path", "manifest_status",
        ])
        for m in records:
            writer.writerow([
                m.sha256, m.date, m.from_, m.to, m.cc, m.subject, m.message_id,
                m.source_paths, m.sha256, m.attachment_count, m.parsing_warnings,
                m.completeness, m.saved_message_path, m.manifest_status,
            ])


def write_attachments_csv(output_dir: Path, records: List[AttachmentRecord]) -> None:
    path = output_dir / "attachments.csv"
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow([
            "message_sha256", "original_filename", "sanitized_filename",
            "saved_relative_path", "content_type", "size_bytes", "sha256",
        ])
        for a in records:
            writer.writerow([
                a.message_sha256, a.original_filename, a.sanitized_filename,
                a.saved_relative_path, a.content_type, a.size_bytes, a.sha256,
            ])


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def run(input_path: Path, output_path: Path, limits: Limits) -> dict:
    output_path.mkdir(parents=True, exist_ok=True)

    safety_events: List[SafetyEvent] = []
    manifest_entries: List[ManifestEntry] = []
    members_seen = 0

    if input_path.is_dir():
        sources, manifest_entries, safety_events = gather_from_dir(input_path, limits)
        members_seen = len(sources)
    elif zipfile.is_zipfile(input_path):
        sources, manifest_entries, safety_events, members_seen = gather_from_zip(input_path, limits)
    else:
        raise ValueError(f"input is neither a directory nor a zip file: {input_path}")

    unique_by_hash, manifest_mismatches = deduplicate(sources, manifest_entries)

    message_records: List[MessageRecord] = []
    attachment_records: List[AttachmentRecord] = []
    failures: List[dict] = []
    partial_count = 0
    duplicate_message_count = 0
    total_attachment_bytes = 0

    for digest in sorted(unique_by_hash.keys()):
        unique = unique_by_hash[digest]
        if len(unique.source_paths) > 1:
            duplicate_message_count += 1

        saved_path = write_message_copy(output_path, unique)

        msg, warnings, _used_fallback = parse_eml(unique.data)
        if msg is None:
            failures.append({"sha256": digest, "sources": unique.source_paths, "error": "; ".join(warnings)})
            message_records.append(MessageRecord(
                sha256=digest, date="", from_="", to="", cc="", subject="",
                message_id="", source_paths=";".join(unique.source_paths),
                attachment_count=0, parsing_warnings="; ".join(warnings),
                completeness="partial", saved_message_path=saved_path,
                manifest_status=unique.manifest_status, body_text="",
            ))
            partial_count += 1
            continue

        completeness, reasons = assess_completeness(unique.data, msg)
        if completeness == "partial":
            partial_count += 1
        all_warnings = warnings + reasons

        try:
            attachments = extract_attachments(msg)
        except Exception as exc:
            attachments = []
            all_warnings.append(f"attachment-extraction-error:{exc}")

        for payload, original_name, ctype in attachments:
            try:
                rel_path, a_sha = write_attachment(output_path, digest, payload, original_name)
            except Exception as exc:
                all_warnings.append(f"attachment-write-error:{exc}")
                continue
            attachment_records.append(AttachmentRecord(
                message_sha256=digest,
                original_filename=original_name,
                sanitized_filename=sanitize_filename(original_name),
                saved_relative_path=rel_path,
                content_type=ctype,
                size_bytes=len(payload),
                sha256=a_sha,
            ))
            total_attachment_bytes += len(payload)

        try:
            body_text = extract_body_text(msg)
        except Exception as exc:
            body_text = ""
            all_warnings.append(f"body-extraction-error:{exc}")

        message_records.append(MessageRecord(
            sha256=digest,
            date=header_str(msg, "date"),
            from_=header_str(msg, "from"),
            to=header_str(msg, "to"),
            cc=header_str(msg, "cc"),
            subject=header_str(msg, "subject"),
            message_id=header_str(msg, "message-id"),
            source_paths=";".join(unique.source_paths),
            attachment_count=len(attachments),
            parsing_warnings="; ".join(all_warnings),
            completeness=completeness,
            saved_message_path=saved_path,
            manifest_status=unique.manifest_status,
            body_text=body_text,
        ))

    write_messages_csv(output_path, message_records)
    write_attachments_csv(output_path, attachment_records)
    fts_available = build_sqlite(output_path, message_records, attachment_records)

    manifest_checked = len(manifest_entries)
    manifest_matched = sum(1 for m in unique_by_hash.values() if m.manifest_status == "matched")
    manifest_mismatched = sum(1 for m in unique_by_hash.values() if m.manifest_status == "mismatched")

    summary = {
        "input": str(input_path),
        "output": str(output_path),
        "source_files_found": members_seen,
        "unique_messages": len(unique_by_hash),
        "duplicate_message_count": duplicate_message_count,
        "total_attachments": len(attachment_records),
        "total_attachment_bytes": total_attachment_bytes,
        "messages_marked_partial": partial_count,
        "parse_failures": len(failures),
        "failures": failures,
        "safety_events": [dataclasses.asdict(e) for e in safety_events],
        "hash_verification": {
            "manifest_present": manifest_checked > 0,
            "total_listed": manifest_checked,
            "matched": manifest_matched,
            "mismatched": manifest_mismatched,
            "mismatch_details": manifest_mismatches,
        },
        "fts5_available": fts_available,
    }

    summary_path = output_path / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")

    return summary


def print_console_summary(summary: dict) -> None:
    print("Offline mail recovery summary")
    print(f"  Source files found:       {summary['source_files_found']}")
    print(f"  Unique messages:          {summary['unique_messages']}")
    print(f"  Duplicate messages:       {summary['duplicate_message_count']}")
    print(f"  Attachments extracted:    {summary['total_attachments']}")
    print(f"  Attachment bytes:         {summary['total_attachment_bytes']}")
    print(f"  Messages marked partial:  {summary['messages_marked_partial']}")
    print(f"  Parse failures:           {summary['parse_failures']}")
    print(f"  Safety events:            {len(summary['safety_events'])}")
    hv = summary["hash_verification"]
    if hv["manifest_present"]:
        print(f"  Manifest hash checks:     {hv['matched']} matched / {hv['mismatched']} mismatched "
              f"(of {hv['total_listed']} listed)")
    else:
        print("  Manifest hash checks:     no manifest.json found")
    print(f"  Output directory:         {summary['output']}")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Recover, index, and de-duplicate .eml messages from a ZIP archive or directory.",
    )
    parser.add_argument("--input", required=True, help="Path to a ZIP archive of .eml files, or a directory of .eml files.")
    parser.add_argument("--output", required=True, help="Directory to write recovery results into.")
    parser.add_argument("--max-members", type=int, default=DEFAULT_MAX_MEMBERS,
                         help=f"Maximum number of archive members to process (default {DEFAULT_MAX_MEMBERS}).")
    parser.add_argument("--max-total-size", type=int, default=DEFAULT_MAX_TOTAL_UNCOMPRESSED,
                         help=f"Maximum total expanded bytes to read (default {DEFAULT_MAX_TOTAL_UNCOMPRESSED}).")
    parser.add_argument("--max-file-size", type=int, default=DEFAULT_MAX_FILE_SIZE,
                         help=f"Maximum size of a single member, in bytes (default {DEFAULT_MAX_FILE_SIZE}).")
    parser.add_argument("--max-compression-ratio", type=float, default=DEFAULT_MAX_COMPRESSION_RATIO,
                         help=f"Maximum allowed uncompressed/compressed ratio per member (default {DEFAULT_MAX_COMPRESSION_RATIO}).")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    input_path = Path(args.input).expanduser()
    output_path = Path(args.output).expanduser()

    if not input_path.exists():
        print(f"error: input path does not exist: {input_path}", file=sys.stderr)
        return 2

    limits = Limits(
        max_members=args.max_members,
        max_total_size=args.max_total_size,
        max_file_size=args.max_file_size,
        max_compression_ratio=args.max_compression_ratio,
    )

    try:
        summary = run(input_path, output_path, limits)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print_console_summary(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
