#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


SCRIPT = Path(__file__).with_name("scan_sensitive.py")


class ScannerBehaviorTests(unittest.TestCase):
    def run_scan(self, *arguments: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        merged_env = os.environ.copy()
        if env:
            merged_env.update(env)
        return subprocess.run(
            [sys.executable, str(SCRIPT), *arguments],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=merged_env,
            check=False,
        )

    def test_detected_value_is_never_echoed(self) -> None:
        secret = "sk-" + "SYNTHETIC_TEST_ONLY_1234567890"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "sample.txt")
            path.write_text(f'api_key = "{secret}"\n', encoding="utf-8")
            result = self.run_scan(str(path))
        self.assertEqual(result.returncode, 1)
        self.assertIn("finding_count=", result.stdout)
        self.assertIn("rule=", result.stdout)
        self.assertNotIn(secret, result.stdout)
        self.assertNotIn(secret, result.stderr)
        self.assertNotIn(directory, result.stdout)

    def test_sensitive_value_in_filename_is_redacted(self) -> None:
        secret = "sk-" + "SYNTHETIC_FILENAME_TEST_1234567890"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, f"evidence-{secret}.txt")
            path.write_text("public body", encoding="utf-8")
            result = self.run_scan(str(path))
        self.assertEqual(result.returncode, 1)
        self.assertIn("KNOWN_SECRET_PREFIX", result.stdout)
        self.assertIn("location=filename", result.stdout)
        self.assertNotIn(secret, result.stdout)
        self.assertNotIn(secret, result.stderr)

    def test_extra_string_in_unknown_filename_is_redacted(self) -> None:
        marker = "SYNTHETIC-FILENAME-MARKER-123456"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, f"{marker}.mystery")
            path.write_bytes(b"unknown")
            result = self.run_scan(str(path), "--extra-string", marker)
        self.assertEqual(result.returncode, 1)
        self.assertIn("status=FINDINGS_AND_INCOMPLETE", result.stdout)
        self.assertIn("unknown_format_not_scanned", result.stdout)
        self.assertIn("location=filename", result.stdout)
        self.assertNotIn(marker, result.stdout)
        self.assertNotIn(marker, result.stderr)

    def test_sensitive_value_in_relative_directory_name_is_detected(self) -> None:
        secret = "sk-" + "SYNTHETIC_DIRECTORY_TEST_1234567890"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory, "scope")
            nested = root / f"evidence-{secret}"
            nested.mkdir(parents=True)
            (nested / "safe.md").write_text("public body", encoding="utf-8")
            result = self.run_scan(str(root))
        self.assertEqual(result.returncode, 1)
        self.assertIn("KNOWN_SECRET_PREFIX", result.stdout)
        self.assertIn("location=path", result.stdout)
        self.assertNotIn(secret, result.stdout)
        self.assertNotIn(secret, result.stderr)

    def test_json_secret_assignment_is_detected_without_value(self) -> None:
        secret = "SYNTHETIC_JSON_SECRET_VALUE_123456"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "settings.json")
            path.write_text(f'{{"client_secret": "{secret}"}}', encoding="utf-8")
            result = self.run_scan(str(path))
        self.assertEqual(result.returncode, 1)
        self.assertIn("GENERIC_SECRET_ASSIGNMENT", result.stdout)
        self.assertNotIn(secret, result.stdout)
        self.assertNotIn(secret, result.stderr)

    def test_utf16_le_without_bom_is_scanned(self) -> None:
        secret = "SYNTHETIC_UTF16_SECRET_VALUE_123456"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "settings.txt")
            path.write_bytes(f'client_secret = "{secret}"'.encode("utf-16-le"))
            result = self.run_scan(str(path))
        self.assertEqual(result.returncode, 1)
        self.assertIn("GENERIC_SECRET_ASSIGNMENT", result.stdout)
        self.assertNotIn(secret, result.stdout)
        self.assertNotIn(secret, result.stderr)

    def test_nul_containing_unrecognized_text_is_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "payload.txt")
            path.write_bytes(b"A\x00B\x00C\x01\x00D")
            result = self.run_scan(str(path))
        self.assertEqual(result.returncode, 2)
        self.assertIn("text_decode_failed_or_binary_content", result.stdout)
        self.assertNotIn("status=NO_FINDINGS", result.stdout)

    def test_common_rule_families_are_detected_without_values(self) -> None:
        authorization = "SYNTHETIC_AUTHORIZATION_VALUE_123456"
        cookie = "SYNTHETIC_COOKIE_VALUE_123456"
        signature = "SYNTHETIC_SIGNATURE_VALUE_123456"
        private_header = "-----BEGIN " + "PRIVATE KEY-----"
        signed_url = f"https://example.invalid/download?sig={signature}"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "headers.txt")
            path.write_text(
                "\n".join(
                    (
                        f"Authorization: Bearer {authorization}",
                        f"Cookie: session={cookie}",
                        private_header,
                        signed_url,
                    )
                ),
                encoding="utf-8",
            )
            result = self.run_scan(str(path))
        self.assertEqual(result.returncode, 1)
        self.assertIn("AUTHORIZATION_HEADER", result.stdout)
        self.assertIn("COOKIE_HEADER", result.stdout)
        self.assertIn("PRIVATE_KEY_BLOCK", result.stdout)
        self.assertIn("SIGNED_OR_TOKENIZED_URL", result.stdout)
        for value in (authorization, cookie, signature, private_header, signed_url):
            self.assertNotIn(value, result.stdout)
            self.assertNotIn(value, result.stderr)

    def test_user_extra_string_from_environment_is_not_echoed(self) -> None:
        marker = "SYNTHETIC-CUSTOM-MARKER-ONLY"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "notes.md")
            path.write_text(f"prefix {marker} suffix", encoding="utf-8")
            result = self.run_scan(
                str(path),
                "--extra-string-env",
                "SANITIZER_TEST_MARKER",
                env={"SANITIZER_TEST_MARKER": marker},
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("USER_EXTRA_STRING_1", result.stdout)
        self.assertNotIn(marker, result.stdout)
        self.assertNotIn(marker, result.stderr)

    def test_clean_supported_text_returns_zero_with_warning(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "safe.md")
            path.write_text("A short public troubleshooting summary.\n", encoding="utf-8")
            result = self.run_scan(str(path), "--json")
        self.assertEqual(result.returncode, 0)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "NO_FINDINGS")
        self.assertEqual(payload["finding_count"], 0)
        self.assertIn("not proof", payload["warning"].lower())

    def test_unknown_file_is_incomplete_not_clean(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "payload.mystery")
            path.write_bytes(b"unknown binary-ish content")
            result = self.run_scan(str(path))
        self.assertEqual(result.returncode, 2)
        self.assertIn("status=INCOMPLETE", result.stdout)
        self.assertIn("unknown_format_not_scanned", result.stdout)
        self.assertNotIn("status=NO_FINDINGS", result.stdout)

    def test_home_directory_is_refused_without_traversal(self) -> None:
        result = self.run_scan(str(Path.home()))
        self.assertEqual(result.returncode, 2)
        self.assertIn("broad_scope_refused", result.stdout)
        self.assertIn("files_seen=0", result.stdout)

    def test_repository_root_is_refused_without_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory, "repo")
            root.mkdir()
            (root / ".git").mkdir()
            (root / "safe.md").write_text("public", encoding="utf-8")
            result = self.run_scan(str(root))
        self.assertEqual(result.returncode, 2)
        self.assertIn("broad_scope_refused", result.stdout)
        self.assertIn("files_seen=0", result.stdout)

    def test_pdf_is_explicitly_unsupported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "document.pdf")
            path.write_bytes(b"%PDF-1.7\n% synthetic test file\n")
            result = self.run_scan(str(path))
        self.assertEqual(result.returncode, 2)
        self.assertIn("unsupported_pdf_requires_pdf_workflow", result.stdout)

    def test_office_xml_is_scanned_without_echoing_value(self) -> None:
        secret = "sk-" + "OFFICE_SYNTHETIC_TEST_1234567890"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "document.docx")
            with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as package:
                package.writestr(
                    "[Content_Types].xml",
                    "<?xml version='1.0'?><Types></Types>",
                )
                package.writestr(
                    "word/document.xml",
                    f"<?xml version='1.0'?><document><text>{secret}</text></document>",
                )
            result = self.run_scan(str(path))
        self.assertEqual(result.returncode, 1)
        self.assertIn("document.docx!word/document.xml", result.stdout)
        self.assertNotIn(secret, result.stdout)
        self.assertNotIn(secret, result.stderr)

    def test_secret_split_across_ooxml_runs_is_detected(self) -> None:
        secret = "sk-" + "SYNTHETIC_OOXML_SPLIT_1234567890"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "document.docx")
            xml = (
                "<w:document xmlns:w='urn:test'><w:body><w:p>"
                "<w:r><w:t>sk-</w:t></w:r>"
                "<w:r><w:t>SYNTHETIC_</w:t></w:r>"
                "<w:r><w:t>OOXML_SPLIT_1234567890</w:t></w:r>"
                "</w:p></w:body></w:document>"
            )
            with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as package:
                package.writestr("word/document.xml", xml)
            result = self.run_scan(str(path))
        self.assertEqual(result.returncode, 1)
        self.assertIn("KNOWN_SECRET_PREFIX", result.stdout)
        self.assertIn("xml-unit:", result.stdout)
        self.assertNotIn(secret, result.stdout)
        self.assertNotIn(secret, result.stderr)

    def test_ooxml_text_is_not_joined_across_paragraphs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "document.docx")
            xml = (
                "<w:document xmlns:w='urn:test'><w:body>"
                "<w:p><w:r><w:t>sk-</w:t></w:r></w:p>"
                "<w:p><w:r><w:t>SYNTHETIC_NOT_SAME_BLOCK_1234567890</w:t></w:r></w:p>"
                "</w:body></w:document>"
            )
            with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as package:
                package.writestr("word/document.xml", xml)
            result = self.run_scan(str(path))
        self.assertEqual(result.returncode, 0)
        self.assertIn("status=NO_FINDINGS", result.stdout)

    def test_office_embedded_image_prevents_clean_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "slides.pptx")
            with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as package:
                package.writestr("ppt/slides/slide1.xml", "<slide><text>Public</text></slide>")
                package.writestr("ppt/media/image1.png", b"synthetic image bytes")
            result = self.run_scan(str(path))
        self.assertEqual(result.returncode, 2)
        self.assertIn("status=INCOMPLETE", result.stdout)
        self.assertIn("office_nontext_part_not_scanned", result.stdout)

    def test_all_unscanned_office_parts_prevent_clean_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "document.docx")
            with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as package:
                package.writestr("word/document.xml", "<document><text>Public</text></document>")
                package.writestr("docProps/thumbnail.jpeg", b"synthetic thumbnail")
                package.writestr("word/activeX/activeX1.bin", b"synthetic activeX")
            result = self.run_scan(str(path))
        self.assertEqual(result.returncode, 2)
        self.assertIn("status=INCOMPLETE", result.stdout)
        self.assertGreaterEqual(result.stdout.count("office_nontext_part_not_scanned"), 2)

    def test_extra_string_in_office_member_name_is_redacted(self) -> None:
        marker = "SYNTHETIC-OFFICE-MEMBER-123456"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "document.docx")
            with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as package:
                package.writestr("word/document.xml", "<document><text>Public</text></document>")
                package.writestr(f"word/media/{marker}.png", b"synthetic image")
            result = self.run_scan(str(path), "--extra-string", marker)
        self.assertEqual(result.returncode, 1)
        self.assertIn("status=FINDINGS_AND_INCOMPLETE", result.stdout)
        self.assertIn("office_nontext_part_not_scanned", result.stdout)
        self.assertIn("location=path", result.stdout)
        self.assertNotIn(marker, result.stdout)
        self.assertNotIn(marker, result.stderr)

    def test_sensitive_value_in_office_member_name_is_detected(self) -> None:
        secret = "sk-" + "SYNTHETIC_MEMBER_TEST_1234567890"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "document.docx")
            with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as package:
                package.writestr("word/document.xml", "<document><text>Public</text></document>")
                package.writestr(f"word/media/{secret}.png", b"synthetic image")
            result = self.run_scan(str(path))
        self.assertEqual(result.returncode, 1)
        self.assertIn("status=FINDINGS_AND_INCOMPLETE", result.stdout)
        self.assertIn("KNOWN_SECRET_PREFIX", result.stdout)
        self.assertIn("location=path", result.stdout)
        self.assertNotIn(secret, result.stdout)
        self.assertNotIn(secret, result.stderr)

    def test_symlink_is_not_followed_when_supported(self) -> None:
        secret = "sk-" + "OUTSIDE_SYNTHETIC_TEST_1234567890"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory, "scope")
            root.mkdir()
            outside = Path(directory, "outside.txt")
            outside.write_text(secret, encoding="utf-8")
            link = root / "linked.txt"
            try:
                link.symlink_to(outside)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation is unavailable on this platform")
            result = self.run_scan(str(root))
        self.assertEqual(result.returncode, 2)
        self.assertIn("symlink_skipped", result.stdout)
        self.assertNotIn(secret, result.stdout)


if __name__ == "__main__":
    unittest.main()
