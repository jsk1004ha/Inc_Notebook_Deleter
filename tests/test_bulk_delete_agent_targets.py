"""Regression tests for the bounded Windows file cleanup utility."""
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import bulk_delete_agent_targets as app


class DeletionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)

    def test_absent_files_not_counted_as_deletions(self):
        results = app.delete_targets(self.folder, retries=0)
        self.assertEqual(len(results), len(app.TARGET_FILES))
        self.assertTrue(all(not item.existed_before for item in results))
        self.assertTrue(all(item.deleted for item in results))

    def test_delete_a_regular_allowlisted_file(self):
        target = self.folder / app.TARGET_FILES[0]
        target.write_text("test content", encoding="utf-8")
        results = app.delete_targets(self.folder, retries=0)
        self.assertFalse(target.exists())
        self.assertTrue(results[0].deleted)
        self.assertTrue(results[0].existed_before)

    def test_dry_run_does_not_change_file(self):
        target = self.folder / app.TARGET_FILES[0]
        target.write_text("keep", encoding="utf-8")
        results = app.delete_targets(self.folder, retries=0, dry_run=True)
        self.assertEqual(target.read_text(encoding="utf-8"), "keep")
        self.assertTrue(results[0].dry_run)
        self.assertFalse(results[0].deleted)

    def test_directory_with_executable_name_is_never_recursively_deleted(self):
        target = self.folder / app.TARGET_FILES[0]
        target.mkdir()
        (target / "important.txt").write_text("keep", encoding="utf-8")
        results = app.delete_targets(self.folder, retries=0)
        self.assertFalse(results[0].deleted)
        self.assertIn("일반 파일", results[0].reason)
        self.assertTrue((target / "important.txt").exists())

    def test_symlink_is_not_followed(self):
        external = self.folder / "safe.txt"
        external.write_text("keep", encoding="utf-8")
        link = self.folder / app.TARGET_FILES[0]
        try:
            link.symlink_to(external)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlinks unavailable: {exc}")
        results = app.delete_targets(self.folder, retries=0)
        self.assertFalse(results[0].deleted)
        self.assertTrue(external.exists())

    def test_error_is_returned_instead_of_hidden(self):
        target = self.folder / app.TARGET_FILES[0]
        target.write_text("keep", encoding="utf-8")
        with mock.patch.object(app, "_delete_once", return_value=(False, "WinError 5: Access is denied")):
            with mock.patch.object(app, "_rm_get_locking_pids", return_value=set()):
                results = app.delete_targets(self.folder, retries=0)
        self.assertFalse(results[0].deleted)
        self.assertIn("WinError 5", results[0].reason)

    def test_dry_run_report_is_not_a_failure(self):
        target = self.folder / app.TARGET_FILES[0]
        target.write_text("keep", encoding="utf-8")
        capture = io.StringIO()
        with redirect_stdout(capture):
            exit_code = app.main(["--target-dir", str(self.folder), "--dry-run"])
        self.assertEqual(exit_code, 0)
        self.assertIn("[예정]", capture.getvalue())
        self.assertIn("실패: 0", capture.getvalue())

    def test_output_encoding_configuration(self):
        mock_out = mock.Mock()
        mock_err = mock.Mock()
        with mock.patch.object(app.sys, "stdout", mock_out):
            with mock.patch.object(app.sys, "stderr", mock_err):
                app._configure_console_encoding()
        mock_out.reconfigure.assert_called_once_with(encoding="utf-8", errors="backslashreplace")
        mock_err.reconfigure.assert_called_once_with(encoding="utf-8", errors="backslashreplace")

    def test_explicit_check_mode_does_not_remove_file(self):
        target = self.folder / app.TARGET_FILES[0]
        target.write_text("preserve", encoding="utf-8")
        with redirect_stdout(io.StringIO()) as captured:
            self.assertEqual(app.main(["--mode", "check", "--target-dir", str(self.folder)]), 0)
        self.assertEqual(target.read_text(encoding="utf-8"), "preserve")
        self.assertIn("[시작] 모드: 검사", captured.getvalue())

    def test_diagnose_overrides_delete_mode(self):
        target = self.folder / app.TARGET_FILES[0]
        target.write_text("preserve", encoding="utf-8")
        with redirect_stdout(io.StringIO()) as captured:
            self.assertEqual(app.main(["--diagnose", "--mode", "delete", "--target-dir", str(self.folder)]), 0)
        self.assertTrue(target.exists())
        self.assertIn("[진단 모드]", captured.getvalue())

    def test_noninteractive_no_args_is_diagnostic_only(self):
        with mock.patch.object(app.sys, "stdin", io.StringIO("")):
            with mock.patch.object(app.sys, "argv", ["script.py"]):
                with mock.patch.object(app, "_run_cli", return_value=0) as runner:
                    self.assertEqual(app.main(), 0)
        runner.assert_called_once_with(["--diagnose"])

    def test_interactive_selection_default_is_safe(self):
        class FakeConsole:
            def isatty(self):
                return True
        with mock.patch.object(app.sys, "stdin", FakeConsole()):
            with mock.patch("builtins.input", side_effect=["", ""]):
                with mock.patch.object(app, "_run_cli", return_value=0) as runner:
                    with redirect_stdout(io.StringIO()):
                        self.assertEqual(app.main([]), 0)
        runner.assert_called_once_with(["--diagnose"])


if __name__ == "__main__":
    unittest.main()
