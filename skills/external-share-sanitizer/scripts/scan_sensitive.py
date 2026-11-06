#!/usr/bin/env python3
"""Read-only sensitive-pattern triage for explicitly scoped share packages.

The scanner never prints matched values or source excerpts. It is intentionally
conservative: unsupported, skipped, linked, oversized, or unknown content makes
the result incomplete rather than clean.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Iterator, Sequence


TEXT_EXTENSIONS = {
    ".bash",
    ".bat",
    ".c",
    ".cfg",
    ".cmd",
    ".conf",
    ".cpp",
    ".cs",
    ".css",
    ".csv",
    ".env",
    ".gql",
    ".go",
    ".graphql",
    ".h",
    ".hpp",
    ".htm",
    ".html",
    ".ini",
    ".java",
    ".js",
    ".json",
    ".jsonl",
    ".jsx",
    ".key",
    ".kt",
    ".kts",
    ".log",
    ".md",
    ".php",
    ".pem",
    ".properties",
    ".ps1",
    ".pub",
    ".py",
    ".rb",
    ".rels",
    ".rs",
    ".scss",
    ".sh",
    ".sql",
    ".svelte",
    ".toml",
    ".ts",
    ".tsv",
    ".tsx",
    ".txt",
    ".vue",
    ".xml",
    ".yaml",
    ".yml",
    ".zsh",
}

TEXT_FILENAMES = {
    ".dockerignore",
    ".editorconfig",
    ".gitattributes",
    ".gitignore",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".curlrc",
    "credentials",
    "dockerfile",
    "gemfile",
    "makefile",
    "procfile",
}

OFFICE_EXTENSIONS = {".docx", ".xlsx", ".pptx"}
IMAGE_EXTENSIONS = {
    ".avif",
    ".bmp",
    ".gif",
    ".heic",
    ".jpeg",
    ".jpg",
    ".png",
    ".tif",
    ".tiff",
    ".webp",
}
MEDIA_EXTENSIONS = {
    ".aac",
    ".avi",
    ".flac",
    ".m4a",
    ".mkv",
    ".mov",
    ".mp3",
    ".mp4",
    ".ogg",
    ".wav",
    ".webm",
}
ARCHIVE_EXTENSIONS = {
    ".7z",
    ".bz2",
    ".gz",
    ".rar",
    ".tar",
    ".tgz",
    ".xz",
    ".zip",
    ".zst",
}
DATABASE_EXTENSIONS = {".db", ".sqlite", ".sqlite3"}
LEGACY_OFFICE_EXTENSIONS = {".doc", ".xls", ".ppt"}


@dataclass(frozen=True)
class PatternRule:
    name: str
    pattern: re.Pattern[str]


RULES = (
    PatternRule(
        "PRIVATE_KEY_BLOCK",
        re.compile(
            r"-----BEGIN\s+(?:(?:RSA|DSA|EC|OPENSSH)\s+)?PRIVATE\s+KEY-----",
            re.IGNORECASE,
        ),
    ),
    PatternRule(
        "AUTHORIZATION_HEADER",
        re.compile(
            r"\b(?:proxy-)?authorization[\"']?\s*[:=]\s*[\"']?"
            r"(?:bearer|basic|token)\s+[^\s\"'`,;]{8,}",
            re.IGNORECASE,
        ),
    ),
    PatternRule(
        "COOKIE_HEADER",
        re.compile(
            r"\b(?:cookie|set-cookie)[\"']?\s*:\s*[\"']?[^\r\n]{8,}",
            re.IGNORECASE,
        ),
    ),
    PatternRule(
        "KNOWN_SECRET_PREFIX",
        re.compile(
            r"\b(?:"
            r"sk-[A-Za-z0-9][A-Za-z0-9_-]{15,}|"
            r"github_pat_[A-Za-z0-9_]{20,}|"
            r"gh[pousr]_[A-Za-z0-9]{20,}|"
            r"AKIA[0-9A-Z]{16}|"
            r"AIza[0-9A-Za-z_-]{30,}|"
            r"xox[baprs]-[A-Za-z0-9-]{12,}"
            r")\b"
        ),
    ),
    PatternRule(
        "JWT_LIKE_TOKEN",
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\."
            r"[A-Za-z0-9_-]{5,}\b"
        ),
    ),
    PatternRule(
        "GENERIC_SECRET_ASSIGNMENT",
        re.compile(
            r"\b(?:"
            r"api[_-]?key|access[_-]?key(?:[_-]?id)?|"
            r"secret[_-]?access[_-]?key|access[_-]?token|"
            r"auth[_-]?token|refresh[_-]?token|session[_-]?token|"
            r"client[_-]?secret|secret[_-]?key|password|passwd"
            r")\b[\"']?\s*[:=]\s*[\"']?"
            r"(?!\$\{|\{\{)[A-Za-z0-9_./+=:@-]{8,}",
            re.IGNORECASE,
        ),
    ),
    PatternRule(
        "SIGNED_OR_TOKENIZED_URL",
        re.compile(
            r"https?://[^\s\"'<>]+\?[^\s\"'<>]*"
            r"(?:x-amz-signature|x-goog-signature|signature|sig|"
            r"access_token|token)=[^&\s\"'<>]+",
            re.IGNORECASE,
        ),
    ),
    PatternRule(
        "CREDENTIAL_IN_URI",
        re.compile(
            r"\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^@\s/]{4,}@",
            re.IGNORECASE,
        ),
    ),
)


@dataclass(frozen=True)
class Finding:
    scope: int
    path: str
    location: str
    rule: str


@dataclass(frozen=True)
class Unscanned:
    scope: int
    path: str
    reason: str


@dataclass(frozen=True)
class Scope:
    index: int
    root: Path
    is_file: bool

    def label(self, path: Path, member: str | None = None) -> str:
        if self.is_file:
            relative = self.root.name
        else:
            try:
                relative = path.relative_to(self.root).as_posix()
            except ValueError:
                relative = path.name
            if relative in {"", "."}:
                relative = "."
        if member is not None:
            return f"{relative}!{member.replace('\\', '/')}"
        return relative


def safe_label(value: str, limit: int = 500) -> str:
    cleaned = "".join(ch if ch.isprintable() and ch not in "\r\n\t" else "?" for ch in value)
    if len(cleaned) > limit:
        return cleaned[: limit - 3] + "..."
    return cleaned


def line_and_column(text: str, offset: int) -> str:
    line = text.count("\n", 0, offset) + 1
    last_newline = text.rfind("\n", 0, offset)
    column = offset + 1 if last_newline < 0 else offset - last_newline
    return f"{line}:{column}"


def decode_text(data: bytes) -> str | None:
    if not data:
        return ""
    if data.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        try:
            return data.decode("utf-32")
        except UnicodeDecodeError:
            return None
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            return None
    if b"\x00" in data:
        if len(data) % 2:
            return None
        even_nuls = data[0::2].count(0)
        odd_nuls = data[1::2].count(0)
        pair_count = max(len(data) // 2, 1)
        candidates: list[str] = []
        if odd_nuls / pair_count >= 0.20 and even_nuls / pair_count <= 0.05:
            candidates.append("utf-16-le")
        if even_nuls / pair_count >= 0.20 and odd_nuls / pair_count <= 0.05:
            candidates.append("utf-16-be")
        for encoding in candidates:
            try:
                decoded = data.decode(encoding)
            except UnicodeDecodeError:
                continue
            if "\x00" not in decoded and is_plausible_text(decoded):
                return decoded
        return None
    for encoding in ("utf-8-sig", "gb18030", "cp1252"):
        try:
            return data.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return None


def is_plausible_text(text: str) -> bool:
    if not text:
        return True
    acceptable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text)
    return acceptable / len(text) >= 0.85


def aggregate_xml_text_units(text: str) -> list[str] | None:
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None
    logical_names = {"p", "si", "c", "comment"}
    units: list[str] = []
    for element in root.iter():
        local_name = element.tag.rsplit("}", 1)[-1]
        if local_name not in logical_names:
            continue
        fragments = [fragment for fragment in element.itertext() if fragment]
        if len(fragments) < 2:
            continue
        units.append("".join(fragments))
    return units


class Scanner:
    def __init__(
        self,
        *,
        max_files: int,
        max_bytes_per_file: int,
        max_total_bytes: int,
        extra_strings: Sequence[str],
    ) -> None:
        self.max_files = max_files
        self.max_bytes_per_file = max_bytes_per_file
        self.max_total_bytes = max_total_bytes
        self.extra_strings = tuple(extra_strings)
        self.findings: list[Finding] = []
        self.unscanned: list[Unscanned] = []
        self.files_seen = 0
        self.files_scanned = 0
        self.bytes_scanned = 0
        self._finding_keys: set[tuple[int, str, str, str]] = set()
        self._unscanned_keys: set[tuple[int, str, str]] = set()

    def add_finding(
        self, scope: Scope, path: Path, location: str, rule: str, member: str | None = None
    ) -> None:
        label = self._report_label(scope.label(path, member))
        key = (scope.index, label, location, rule)
        if key not in self._finding_keys:
            self._finding_keys.add(key)
            self.findings.append(Finding(scope.index, label, location, rule))

    def add_unscanned(
        self, scope: Scope, path: Path, reason: str, member: str | None = None
    ) -> None:
        label = self._report_label(scope.label(path, member))
        key = (scope.index, label, reason)
        if key not in self._unscanned_keys:
            self._unscanned_keys.add(key)
            self.unscanned.append(Unscanned(scope.index, label, reason))

    def _report_label(self, raw_label: str) -> str:
        redacted = raw_label
        for value in sorted(self.extra_strings, key=len, reverse=True):
            redacted = redacted.replace(value, "[USER_EXTRA_STRING]")
        for rule in RULES:
            redacted = rule.pattern.sub(f"[{rule.name}]", redacted)
        return safe_label(redacted)

    def scan_scope(self, scope: Scope) -> None:
        self._scan_name(
            scope,
            scope.root,
            scope.root.name,
            "filename" if scope.is_file else "path",
        )
        if is_link_or_reparse(scope.root):
            self.add_unscanned(scope, scope.root, "symlink_target_refused")
            return
        if scope.is_file:
            self._scan_counted_file(scope, scope.root)
            return
        if is_broad_directory(scope.root) or is_repository_or_vault_root(scope.root):
            self.add_unscanned(scope, scope.root, "broad_scope_refused")
            return
        for path in self._iter_directory(scope, scope.root):
            if self.files_seen >= self.max_files:
                self.add_unscanned(scope, scope.root, "max_files_limit_reached")
                return
            self._scan_counted_file(scope, path)

    def _iter_directory(self, scope: Scope, root: Path) -> Iterator[Path]:
        stack = [root]
        while stack:
            current = stack.pop()
            try:
                with os.scandir(current) as iterator:
                    entries = sorted(iterator, key=lambda item: item.name.casefold(), reverse=True)
            except OSError:
                self.add_unscanned(scope, current, "directory_access_error")
                continue
            child_directories: list[Path] = []
            files: list[Path] = []
            for entry in entries:
                entry_path = Path(entry.path)
                try:
                    self._scan_name(scope, entry_path, entry.name, "path")
                    if entry.is_symlink() or is_reparse_stat(entry.stat(follow_symlinks=False)):
                        self.add_unscanned(scope, entry_path, "symlink_skipped")
                    elif entry.is_dir(follow_symlinks=False):
                        child_directories.append(entry_path)
                    elif entry.is_file(follow_symlinks=False):
                        files.append(entry_path)
                    else:
                        self.add_unscanned(scope, entry_path, "non_regular_file_skipped")
                except OSError:
                    self.add_unscanned(scope, entry_path, "entry_access_error")
            for path in reversed(files):
                yield path
            stack.extend(child_directories)

    def _scan_counted_file(self, scope: Scope, path: Path) -> None:
        if self.files_seen >= self.max_files:
            self.add_unscanned(scope, path, "max_files_limit_reached")
            return
        self.files_seen += 1
        extension = path.suffix.lower()
        filename = path.name.casefold()
        if extension in OFFICE_EXTENSIONS:
            self._scan_office(scope, path)
        elif extension == ".pdf":
            self.add_unscanned(scope, path, "unsupported_pdf_requires_pdf_workflow")
        elif extension in IMAGE_EXTENSIONS:
            self.add_unscanned(scope, path, "unsupported_image_requires_visual_review")
        elif extension in MEDIA_EXTENSIONS:
            self.add_unscanned(scope, path, "unsupported_media_requires_media_review")
        elif extension in ARCHIVE_EXTENSIONS:
            self.add_unscanned(scope, path, "unsupported_archive_format")
        elif extension in DATABASE_EXTENSIONS:
            self.add_unscanned(scope, path, "unsupported_database_format")
        elif extension in LEGACY_OFFICE_EXTENSIONS:
            self.add_unscanned(scope, path, "unsupported_legacy_office_format")
        elif extension in TEXT_EXTENSIONS or filename in TEXT_FILENAMES:
            self._scan_text_file(scope, path)
        else:
            self.add_unscanned(scope, path, "unknown_format_not_scanned")

    def _scan_text_file(self, scope: Scope, path: Path) -> None:
        try:
            size = path.stat().st_size
        except OSError:
            self.add_unscanned(scope, path, "file_stat_error")
            return
        if size > self.max_bytes_per_file:
            self.add_unscanned(scope, path, "max_bytes_per_file_exceeded")
            return
        if self.bytes_scanned + size > self.max_total_bytes:
            self.add_unscanned(scope, path, "max_total_bytes_exceeded")
            return
        try:
            data = path.read_bytes()
        except OSError:
            self.add_unscanned(scope, path, "file_read_error")
            return
        text = decode_text(data)
        if text is None:
            self.add_unscanned(scope, path, "text_decode_failed_or_binary_content")
            return
        self.bytes_scanned += len(data)
        self.files_scanned += 1
        self._scan_text(scope, path, text)

    def _scan_office(self, scope: Scope, path: Path) -> None:
        try:
            package_size = path.stat().st_size
        except OSError:
            self.add_unscanned(scope, path, "file_stat_error")
            return
        if package_size > self.max_bytes_per_file:
            self.add_unscanned(scope, path, "max_bytes_per_file_exceeded")
            return
        try:
            with zipfile.ZipFile(path) as package:
                members = package.infolist()
                if len(members) > self.max_files:
                    self.add_unscanned(scope, path, "office_package_member_limit_exceeded")
                    return
                scanned_member = False
                package_incomplete = False
                for info in sorted(members, key=lambda item: item.filename.casefold()):
                    if info.is_dir():
                        continue
                    member = info.filename.replace("\\", "/")
                    self._scan_name(scope, path, member, "path", member)
                    suffix = Path(member).suffix.lower()
                    if suffix in {".xml", ".rels", ".txt", ".csv"}:
                        if info.file_size > self.max_bytes_per_file:
                            self.add_unscanned(
                                scope, path, "office_xml_member_too_large", member
                            )
                            package_incomplete = True
                            continue
                        if self.bytes_scanned + info.file_size > self.max_total_bytes:
                            self.add_unscanned(
                                scope, path, "max_total_bytes_exceeded", member
                            )
                            package_incomplete = True
                            continue
                        if (
                            info.file_size > 1_000_000
                            and info.file_size > max(info.compress_size, 1) * 100
                        ):
                            self.add_unscanned(
                                scope, path, "suspicious_office_compression_ratio", member
                            )
                            package_incomplete = True
                            continue
                        try:
                            data = package.read(info)
                        except (OSError, RuntimeError, zipfile.BadZipFile):
                            self.add_unscanned(
                                scope, path, "office_xml_member_read_error", member
                            )
                            package_incomplete = True
                            continue
                        text = decode_text(data)
                        if text is None:
                            self.add_unscanned(
                                scope, path, "office_xml_member_decode_failed", member
                            )
                            package_incomplete = True
                            continue
                        self.bytes_scanned += len(data)
                        scanned_member = True
                        self._scan_text(scope, path, text, member)
                        if suffix in {".xml", ".rels"}:
                            units = aggregate_xml_text_units(text)
                            if units is None:
                                self.add_unscanned(
                                    scope,
                                    path,
                                    "office_xml_parse_failed_for_text_aggregation",
                                    member,
                                )
                                package_incomplete = True
                            else:
                                for unit_index, unit in enumerate(units, start=1):
                                    self._scan_text(
                                        scope,
                                        path,
                                        unit,
                                        member,
                                        xml_unit=unit_index,
                                    )
                    else:
                        self.add_unscanned(
                            scope, path, "office_nontext_part_not_scanned", member
                        )
                        package_incomplete = True
                if scanned_member:
                    self.files_scanned += 1
                else:
                    self.add_unscanned(scope, path, "office_package_has_no_scannable_xml")
                if package_incomplete and not scanned_member:
                    return
        except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile):
            self.add_unscanned(scope, path, "invalid_or_unreadable_office_package")

    def _scan_name(
        self,
        scope: Scope,
        path: Path,
        text: str,
        location: str,
        member: str | None = None,
    ) -> None:
        for rule in RULES:
            if rule.pattern.search(text):
                self.add_finding(scope, path, location, rule.name, member)
        for index, value in enumerate(self.extra_strings, start=1):
            if value in text:
                self.add_finding(
                    scope,
                    path,
                    location,
                    f"USER_EXTRA_STRING_{index}",
                    member,
                )

    def _scan_text(
        self,
        scope: Scope,
        path: Path,
        text: str,
        member: str | None = None,
        xml_unit: int | None = None,
    ) -> None:
        for rule in RULES:
            for match in rule.pattern.finditer(text):
                location = (
                    f"xml-unit:{xml_unit}:{match.start() + 1}"
                    if xml_unit is not None
                    else line_and_column(text, match.start())
                )
                self.add_finding(
                    scope, path, location, rule.name, member
                )
        for index, value in enumerate(self.extra_strings, start=1):
            start = 0
            while True:
                match_at = text.find(value, start)
                if match_at < 0:
                    break
                location = (
                    f"xml-unit:{xml_unit}:{match_at + 1}"
                    if xml_unit is not None
                    else line_and_column(text, match_at)
                )
                self.add_finding(
                    scope,
                    path,
                    location,
                    f"USER_EXTRA_STRING_{index}",
                    member,
                )
                start = match_at + max(len(value), 1)


def is_reparse_stat(stat_result: os.stat_result) -> bool:
    attributes = getattr(stat_result, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(attributes and reparse_flag and attributes & reparse_flag)


def is_link_or_reparse(path: Path) -> bool:
    try:
        return path.is_symlink() or is_reparse_stat(path.lstat())
    except OSError:
        return False


def is_broad_directory(path: Path) -> bool:
    absolute = Path(os.path.abspath(path))
    normalized = os.path.normcase(str(absolute))
    root = os.path.normcase(str(Path(absolute.anchor))) if absolute.anchor else ""
    home = os.path.normcase(str(Path.home().absolute()))
    return normalized in {root, home}


def is_repository_or_vault_root(path: Path) -> bool:
    return (path / ".git").exists() or (path / ".obsidian").exists()


def positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def load_extra_strings(args: argparse.Namespace, parser: argparse.ArgumentParser) -> list[str]:
    values: list[str] = list(args.extra_string)
    for index, filename in enumerate(args.extra_strings_file, start=1):
        extra_path = Path(filename)
        if is_link_or_reparse(extra_path):
            parser.error(f"extra-strings file #{index} must not be a link or reparse point")
        try:
            lines = extra_path.read_text(encoding="utf-8-sig").splitlines()
        except (OSError, UnicodeError):
            parser.error(f"could not read extra-strings file #{index}")
        values.extend(line for line in lines if line)
    for index, variable in enumerate(args.extra_string_env, start=1):
        value = os.environ.get(variable)
        if value is None:
            parser.error(f"extra-string environment variable #{index} is not set")
        values.append(value)
    deduplicated: list[str] = []
    seen: set[str] = set()
    for index, value in enumerate(values, start=1):
        if len(value) < 4:
            parser.error(f"extra string #{index} must contain at least four characters")
        if value not in seen:
            seen.add(value)
            deduplicated.append(value)
    return deduplicated


def target_scope(index: int, raw_target: str) -> tuple[Scope, bool]:
    path = Path(os.path.abspath(os.path.expanduser(raw_target)))
    return Scope(index=index, root=path, is_file=path.is_file()), path.exists()


def determine_status(scanner: Scanner) -> tuple[str, int]:
    if scanner.findings and scanner.unscanned:
        return "FINDINGS_AND_INCOMPLETE", 1
    if scanner.findings:
        return "FINDINGS", 1
    if scanner.unscanned:
        return "INCOMPLETE", 2
    return "NO_FINDINGS", 0


def emit_result(scanner: Scanner, scope_count: int, as_json: bool) -> int:
    status, exit_code = determine_status(scanner)
    findings = sorted(
        scanner.findings,
        key=lambda item: (item.scope, item.path.casefold(), item.location, item.rule),
    )
    unscanned = sorted(
        scanner.unscanned,
        key=lambda item: (item.scope, item.path.casefold(), item.reason),
    )
    warning = (
        "This scanner is a triage aid. No findings is not proof that material is "
        "safe to share; semantic and format-specific review is still required."
    )
    if as_json:
        payload = {
            "status": status,
            "scope_count": scope_count,
            "files_seen": scanner.files_seen,
            "files_scanned": scanner.files_scanned,
            "bytes_scanned": scanner.bytes_scanned,
            "finding_count": len(findings),
            "unscanned_count": len(unscanned),
            "findings": [asdict(item) for item in findings],
            "unscanned": [asdict(item) for item in unscanned],
            "warning": warning,
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"status={status}")
        print(f"scope_count={scope_count}")
        print(f"files_seen={scanner.files_seen}")
        print(f"files_scanned={scanner.files_scanned}")
        print(f"bytes_scanned={scanner.bytes_scanned}")
        print(f"finding_count={len(findings)}")
        print(f"unscanned_count={len(unscanned)}")
        for item in findings:
            print(
                f"finding scope={item.scope} path={item.path} "
                f"location={item.location} rule={item.rule}"
            )
        for item in unscanned:
            print(
                f"unscanned scope={item.scope} path={item.path} reason={item.reason}"
            )
        print(f"warning={warning}")
    return exit_code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Read-only sensitive-pattern triage for explicitly scoped files. "
            "Matched values and source excerpts are never printed."
        )
    )
    parser.add_argument("targets", nargs="+", help="explicit file or narrow directory")
    parser.add_argument(
        "--extra-string",
        action="append",
        default=[],
        help="exact user-provided string to detect; the value is never printed",
    )
    parser.add_argument(
        "--extra-strings-file",
        action="append",
        default=[],
        help="UTF-8 file containing one exact comparison string per line",
    )
    parser.add_argument(
        "--extra-string-env",
        action="append",
        default=[],
        help="environment variable whose value should be detected",
    )
    parser.add_argument("--max-files", type=positive_int, default=5000)
    parser.add_argument("--max-bytes-per-file", type=positive_int, default=10_000_000)
    parser.add_argument("--max-total-bytes", type=positive_int, default=100_000_000)
    parser.add_argument("--json", action="store_true", help="emit structured JSON")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    extra_strings = load_extra_strings(args, parser)
    scanner = Scanner(
        max_files=args.max_files,
        max_bytes_per_file=args.max_bytes_per_file,
        max_total_bytes=args.max_total_bytes,
        extra_strings=extra_strings,
    )
    scopes: list[Scope] = []
    for index, raw_target in enumerate(args.targets, start=1):
        scope, exists = target_scope(index, raw_target)
        scopes.append(scope)
        if not exists:
            scanner.add_unscanned(scope, scope.root, "target_not_found")
            continue
        if not scope.root.is_file() and not scope.root.is_dir():
            scanner.add_unscanned(scope, scope.root, "target_is_not_regular_file_or_directory")
            continue
        scanner.scan_scope(scope)
    return emit_result(scanner, len(scopes), args.json)


if __name__ == "__main__":
    raise SystemExit(main())
