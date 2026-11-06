"""Verify installation preserves existing work and confines copies."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "install.py"
SPEC = importlib.util.spec_from_file_location("skill_install", SCRIPT)
INSTALLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALLER)


class InstallationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        for name in ("alpha", "beta"):
            (self.source / name).mkdir(parents=True)
            (self.source / name / "SKILL.md").write_text(f"name: {name}\n", encoding="utf-8")
        self.destination = self.root / "installed"

    def test_selected_skill_is_copied(self):
        targets = INSTALLER.install(["alpha"], self.destination, self.source)
        self.assertEqual(targets, [(self.destination / "alpha").resolve()])
        self.assertEqual((targets[0] / "SKILL.md").read_bytes(), (self.source / "alpha" / "SKILL.md").read_bytes())
        self.assertFalse((self.destination / "beta").exists())

    def test_conflict_prevents_all_copies_and_preserves_existing_file(self):
        existing = self.destination / "beta"
        existing.mkdir(parents=True)
        marker = existing / "SKILL.md"
        marker.write_text("user customization", encoding="utf-8")
        with self.assertRaises(FileExistsError):
            INSTALLER.install(["alpha", "beta"], self.destination, self.source)
        self.assertFalse((self.destination / "alpha").exists())
        self.assertEqual(marker.read_text(encoding="utf-8"), "user customization")

    def test_unknown_or_traversing_name_is_rejected_before_writes(self):
        for name in ("unknown", "../outside"):
            with self.assertRaises(ValueError):
                INSTALLER.install([name], self.destination, self.source)
        self.assertFalse(self.destination.exists())

    def test_nested_destination_is_rejected(self):
        with self.assertRaises(ValueError):
            INSTALLER.install(["alpha"], self.source / "alpha" / "nested", self.source)
        self.assertFalse((self.source / "alpha" / "nested").exists())

    def test_duplicate_names_are_installed_once(self):
        self.assertEqual(len(INSTALLER.install(["alpha", "alpha"], self.destination, self.source)), 1)

    def test_bytecode_is_not_copied(self):
        cache = self.source / "alpha" / "__pycache__"
        cache.mkdir()
        (cache / "cache.pyc").write_bytes(b"synthetic bytecode")
        INSTALLER.install(["alpha"], self.destination, self.source)
        self.assertFalse((self.destination / "alpha" / "__pycache__").exists())

    def test_existing_regular_file_is_preserved(self):
        self.destination.mkdir()
        target = self.destination / "alpha"
        target.write_text("existing file", encoding="utf-8")
        with self.assertRaises(FileExistsError):
            INSTALLER.install(["alpha"], self.destination, self.source)
        self.assertEqual(target.read_text(encoding="utf-8"), "existing file")


if __name__ == "__main__":
    unittest.main()
