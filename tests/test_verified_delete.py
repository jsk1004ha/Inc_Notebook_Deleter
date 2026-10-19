import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import verified_delete as app


class VerifiedDeleteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'allowed'
        self.root.mkdir()
        self.log = Path(self.tmp.name) / 'audit.jsonl'
        self.path = self.root / app.TARGETS[0]
        self.path.write_bytes(b'example file')

    def call(self, *args):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = app.main(['--target-dir', str(self.root), '--log-file', str(self.log), *args])
        return code, stdout.getvalue(), stderr.getvalue()

    def test_default_is_preview(self):
        code, out, err = self.call()
        self.assertEqual(code, 0)
        self.assertTrue(self.path.exists())
        self.assertIn('PREVIEW', out)
        self.assertIn('--execute', out)

    def test_explicit_confirmation_deletes_real_file(self):
        token = app.confirmation_token(app.normalize_directory(self.root))
        code, out, err = self.call('--execute', '--confirm', token)
        self.assertEqual(code, 0)
        self.assertFalse(self.path.exists())
        self.assertIn('SUCCESS', out)
        lines = [json.loads(x) for x in self.log.read_text().splitlines()]
        self.assertEqual(lines[0]['status'], 'deleted')

    def test_wrong_confirmation_does_not_delete(self):
        code, out, err = self.call('--execute', '--confirm', 'invalid')
        self.assertEqual(code, 2)
        self.assertTrue(self.path.exists())

    def test_symlink_file_is_blocked(self):
        self.path.unlink()
        outside = Path(self.tmp.name)/'valuable.txt'
        outside.write_bytes(b'keep')
        try:
            self.path.symlink_to(outside)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(str(exc))
        token = app.confirmation_token(app.normalize_directory(self.root))
        code, out, err = self.call('--execute', '--confirm', token)
        self.assertEqual(code, 1)
        self.assertTrue(outside.exists())
        self.assertTrue(self.path.is_symlink())
        self.assertIn('FAILED', out)

    def test_directory_named_like_file_is_blocked(self):
        self.path.unlink()
        self.path.mkdir()
        (self.path/'retain.txt').write_text('keep')
        token = app.confirmation_token(app.normalize_directory(self.root))
        code, out, err = self.call('--execute', '--confirm', token)
        self.assertEqual(code, 1)
        self.assertTrue((self.path/'retain.txt').exists())

    def test_parent_link_is_rejected(self):
        link = Path(self.tmp.name)/'link'
        try:
            link.symlink_to(self.root, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(str(exc))
        with self.assertRaises(ValueError):
            app.normalize_directory(link)

    def test_parent_traversal_is_rejected(self):
        with self.assertRaises(ValueError):
            app.normalize_directory(self.root/'..'/'allowed')

    def test_real_os_denial_is_reported_not_faked(self):
        token = app.confirmation_token(app.normalize_directory(self.root))
        with patch.object(Path, 'unlink', side_effect=PermissionError(13,'Access denied')):
            code, out, err = self.call('--execute', '--confirm', token)
        self.assertEqual(code, 1)
        self.assertTrue(self.path.exists())
        self.assertIn('FAILED', out)
        self.assertIn('Access denied', out)

    def test_unlink_noop_never_counted_as_deleted(self):
        token = app.confirmation_token(app.normalize_directory(self.root))
        with patch.object(Path, 'unlink', return_value=None):
            code, out, err = self.call('--execute', '--confirm', token)
        self.assertEqual(code, 1)
        self.assertTrue(self.path.exists())
        self.assertIn('삭제 호출 후 재검사 결과', out)

    def test_multiple_files_only_allowlist(self):
        other = self.root/'important.txt'
        other.write_bytes(b'keep')
        extra = self.root/app.TARGETS[1]
        extra.write_bytes(b'remove')
        token = app.confirmation_token(app.normalize_directory(self.root))
        code, out, err = self.call('--execute', '--confirm', token)
        self.assertEqual(code, 0)
        self.assertTrue(other.exists())
        self.assertFalse(extra.exists())
        self.assertFalse(self.path.exists())


if __name__ == '__main__':
    unittest.main()
