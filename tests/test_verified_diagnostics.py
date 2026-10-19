"""Read-only and report generation regression checks; safe on any OS."""
import base64
import contextlib
import hashlib
import io
import json
import subprocess
import tempfile
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

import verified_delete as app


class IncidentDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'selected-folder'
        self.root.mkdir()
        self.file = self.root / app.TARGETS[0]
        self.file.write_bytes(b'incident-test-data')
        self.report_root = Path(self.temp.name) / 'reports'

    def execute(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            result = app.main([
                '--target-dir', str(self.root),
                *args,
            ])
        return result, out.getvalue(), err.getvalue()

    def test_report_produces_json_and_text_and_never_deletes(self):
        with patch.object(Path, 'unlink', side_effect=AssertionError('Deletion not allowed')):
            code, stdout, stderr = self.execute(
                '--analyze-protection', '--report-dir', str(self.report_root)
            )
        self.assertEqual(code, 0, stderr)
        self.assertTrue(self.file.exists())
        reports = list(self.report_root.glob('*.json'))
        texts = list(self.report_root.glob('*.txt'))
        self.assertEqual(len(reports), 1)
        self.assertEqual(len(texts), 1)
        data = json.loads(reports[0].read_text(encoding='utf-8'))
        self.assertEqual(data['files'][0]['sha256'], hashlib.sha256(b'incident-test-data').hexdigest())
        self.assertEqual(data['files'][0]['name'], app.TARGETS[0])
        self.assertEqual(data['files'][1]['state'], 'missing')
        self.assertIn('읽기 전용', texts[0].read_text(encoding='utf-8'))
        self.assertIn('텍스트 보고서:', stdout)

    def test_analysis_and_execute_cannot_coexist(self):
        code, out, err = self.execute('--analyze-protection', '--execute')
        self.assertEqual(code, 2)
        self.assertTrue(self.file.exists())
        self.assertIn('옵션 오류', err)
        self.assertFalse(self.report_root.exists())

    def test_analysis_rejects_confirmation(self):
        code, out, err = self.execute('--analyze-protection', '--confirm', 'anything')
        self.assertEqual(code, 2)
        self.assertTrue(self.file.exists())

    def test_report_folder_cannot_be_target(self):
        code, _, err = self.execute('--analyze-protection', '--report-dir', str(self.root))
        self.assertEqual(code, 3)
        self.assertIn('대상 폴더 밖', err)
        self.assertTrue(self.file.exists())

    def test_report_folder_cannot_be_inside_target(self):
        code, _, err = self.execute('--analyze-protection', '--report-dir', str(self.root / 'reports'))
        self.assertEqual(code, 3)
        self.assertTrue(self.file.exists())

    def test_watch_without_analysis_is_rejected(self):
        code, _, err = self.execute('--watch-seconds', '10')
        self.assertEqual(code, 2)
        self.assertIn('--analyze-protection', err)

    def test_watch_out_of_range_rejected(self):
        code, _, err = self.execute('--analyze-protection', '--watch-seconds', '301')
        self.assertEqual(code, 3)
        self.assertIn('0~300', err)
        self.assertTrue(self.file.exists())

    def test_report_path_with_symlink_ancestor_is_rejected(self):
        external = Path(self.temp.name) / 'outside'
        external.mkdir()
        link = Path(self.temp.name) / 'link-reports'
        try:
            link.symlink_to(external, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(str(exc))
        code, _, err = self.execute('--analyze-protection', '--report-dir', str(link / 'results'))
        self.assertEqual(code, 3)
        self.assertIn('재분석 지점', err)

    def test_encoded_powershell_under_windows_command_line_limit(self):
        encoded_len = len(base64.b64encode(app._WINDOWS_PROBE.encode('utf-16le')))
        self.assertLess(encoded_len, 31000)

    def test_file_symlink_is_not_hashed(self):
        self.file.unlink()
        other = Path(self.temp.name) / 'outside-file'
        other.write_bytes(b'not-to-be-followed')
        try:
            self.file.symlink_to(other)
        except (OSError, NotImplementedError) as ex:
            self.skipTest(str(ex))
        report, _, _ = app.analyze_protection(self.root, report_dir=self.report_root)
        self.assertEqual(report['files'][0]['state'], 'unsafe: symbolic link/reparse point')
        self.assertNotIn('sha256', report['files'][0])
        self.assertEqual(other.read_bytes(), b'not-to-be-followed')

    def test_windows_powershell_json_parser(self):
        mock_data = {
            'targets': [], 'services': [{'name': 'Example'}],
            'drivers': [], 'scheduled_tasks': [], 'startup_entries': [],
            'events': [], 'errors': []
        }
        encoded = base64.b64encode(json.dumps(mock_data).encode()).decode('ascii')
        fake = subprocess.CompletedProcess(['powershell'], 0, stdout=(f'INC_NOTEBOOK_JSON:{encoded}\n').encode(), stderr=b'')
        with patch('shutil.which', return_value='powershell.exe'):
            with patch('subprocess.run', return_value=fake) as run:
                answer = app._windows_powershell_probe(self.root)
        self.assertEqual(answer['services'][0]['name'], 'Example')
        self.assertIn('-EncodedCommand', run.call_args.args[0])
        self.assertEqual(run.call_args.kwargs['env']['INC_NOTEBOOK_TARGET_DIR'], str(self.root))

    def test_probe_failure_never_raises(self):
        with patch('shutil.which', return_value='powershell.exe'):
            with patch('subprocess.run', side_effect=subprocess.TimeoutExpired('powershell.exe', 100)):
                result = app._windows_powershell_probe(self.root)
        self.assertIn('PowerShell query failed', result['errors'][0])

    def test_uninstall_inventory_is_read_only_and_parses_results(self):
        entries = [{'display_name': 'Example JNESS product',
                    'publisher': 'JNESS', 'uninstall_command': 'uninstall.exe'}]
        payload = base64.b64encode(json.dumps(entries).encode('utf-8')).decode('ascii')
        proc = subprocess.CompletedProcess(
            ['powershell'], 0, stdout=('INC_UNINSTALL_JSON:' + payload + '\n').encode(), stderr=b''
        )
        with patch.object(app.os, 'name', 'nt'):
            with patch('shutil.which', return_value='powershell.exe'):
                with patch('subprocess.run', return_value=proc) as run:
                    result, error = app._windows_uninstall_inventory()
        self.assertIsNone(error)
        self.assertEqual(result[0]['display_name'], 'Example JNESS product')
        self.assertIn('-EncodedCommand', run.call_args.args[0])
        self.assertFalse(any('uninstall.exe' == item for item in run.call_args.args[0]))

    def test_uninstall_inventory_failure_is_reported(self):
        with patch.object(app.os, 'name', 'nt'):
            with patch('shutil.which', return_value='powershell.exe'):
                with patch('subprocess.run', side_effect=subprocess.TimeoutExpired('powershell', 40)):
                    result, error = app._windows_uninstall_inventory()
        self.assertEqual(result, [])
        self.assertIn('등록 정보 조회 실패', error)

    def test_probe_absent_executable(self):
        with patch('shutil.which', return_value=None):
            result = app._windows_powershell_probe(self.root)
        self.assertIn('not found', result['errors'][0])

    def test_changes_during_watch_are_observed(self):
        initial = {n: {'state': 'missing'} for n in app.TARGETS}
        updated = {n: {'state': 'missing'} for n in app.TARGETS}
        updated[app.TARGETS[0]] = {'state': 'regular', 'size': 10}
        with patch.object(app, '_target_snapshot', side_effect=[initial, updated]):
            with patch.object(app.time, 'monotonic', side_effect=[0.0, 0.1, 0.1, 1.1]):
                with patch.object(app.time, 'sleep'):
                    changes = app._monitor_changes(self.root, 1)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0]['file'], app.TARGETS[0])
        self.assertEqual(changes[0]['before']['state'], 'missing')
        self.assertEqual(changes[0]['after']['state'], 'regular')


if __name__ == '__main__':
    unittest.main()
