"""Regression tests for evidence-scoped read-only removal assessment."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

import removal_assessment as assessment
import verified_delete as app


class ReferenceAssessmentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'allowed'
        self.root.mkdir()
        self.file = self.root / app.TARGETS[0]
        self.file.write_bytes(b'sample binary')
        self.ref = {
            'schema_version': 1, 'captured_utc': '2026-10-19T05:00:00Z',
            'target_dir': str(self.root), 'admin': False,
            'files': [
                {'name': app.TARGETS[0], 'state': 'regular', 'sha256': app._sha256_readonly(self.file)},
                *({'name': n, 'state': 'missing'} for n in app.TARGETS[1:]),
            ],
            'windows_data': {
                'targets': [{
                    'name': app.TARGETS[0], 'owner': 'NT AUTHORITY\\SYSTEM',
                    'acl': {'rules': [
                        {'principal': 'Everyone', 'type': 'Deny', 'rights': 'Delete', 'inherited': False},
                        {'principal': 'BUILTIN\\Administrators', 'type': 'Allow', 'rights': 'FullControl'},
                    ]},
                }],
                'services': [{'name':'SvcMayaEC','state':'Running', 'account':'LocalSystem',
                              'path': str(self.file), 'pid':333}],
                'processes': [{'pid':333,'name':app.TARGETS[0]}],
                'drivers': [], 'scheduled_tasks': [], 'startup_entries': [], 'events': [],
            },
        }
        self.ref_path = Path(self.tmp.name) / 'reference.json'
        self.save()

    def save(self):
        self.ref_path.write_text(json.dumps(self.ref, ensure_ascii=False), encoding='utf-8')

    def command(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = app.main(['--target-dir', str(self.root),
                             '--log-file', str(Path(self.tmp.name)/'audit.jsonl'), *args])
        return code, out.getvalue(), err.getvalue()

    def test_acl_and_service_report_match(self):
        item = assessment.assess_report(self.ref)
        row = next(x for x in item['files'] if x['name']==app.TARGETS[0])
        self.assertEqual(item['acl_deny_count'], 1)
        self.assertEqual(item['matched_running_service_count'], 1)
        self.assertEqual(row['classification'], 'acl_restriction')
        self.assertEqual(row['running_services'][0]['name'], 'SvcMayaEC')
        self.assertIn('SYSTEM', row['owner'])

    def test_signed_approval_does_not_override_deny(self):
        self.assertTrue(assessment._is_delete_deny({
            'principal':'Everyone', 'type':'Deny', 'rights':'Delete'
        }))
        self.assertTrue(assessment._is_delete_deny({
            'principal':'S-1-1-0', 'type':'Deny', 'rights':'Delete'
        }))
        self.assertFalse(assessment._is_delete_deny({
            'principal':'Everyone', 'type':'Allow', 'rights':'FullControl'
        }))
        self.assertFalse(assessment._is_delete_deny({
            'principal':'BUILTIN\\Users','type':'Deny','rights':'Delete'
        }))
        self.assertFalse(assessment._is_delete_deny({
            'principal':'Everyone', 'type':'Deny', 'rights':'Read'
        }))

    def test_load_plain_report(self):
        r=assessment.load_reference_report(self.ref_path, self.root)
        self.assertEqual(r['files'][0]['name'], app.TARGETS[0])

    def test_load_zip_uses_latest_timestamp_without_extracting(self):
        archive = Path(self.tmp.name) / 'collection.zip'
        earlier = dict(self.ref, captured_utc='2026-10-18T03:00:00Z')
        with zipfile.ZipFile(archive, 'w') as z:
            z.writestr('one.json', json.dumps(earlier))
            z.writestr('subfolder/two.json', json.dumps(self.ref))
        r=assessment.load_reference_report(archive, self.root)
        self.assertEqual(r['captured_utc'], self.ref['captured_utc'])
        self.assertFalse((Path(self.tmp.name)/'subfolder').exists())

    def test_baseline_wrong_directory_rejected(self):
        with self.assertRaisesRegex(ValueError, '대상 폴더'):
            assessment.load_reference_report(self.ref_path, Path(self.tmp.name)/'other')

    def test_disallows_other_target(self):
        self.ref['files'][0]['name'] = 'explorer.exe'
        self.save()
        with self.assertRaisesRegex(ValueError, '승인 범위'):
            assessment.load_reference_report(self.ref_path, self.root)

    def test_invalid_sha256_rejected(self):
        self.ref['files'][0]['sha256'] = 'not a hash'
        self.save()
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            assessment.load_reference_report(self.ref_path, self.root)

    def test_zip_size_limits(self):
        archive = Path(self.tmp.name) / 'oversize.zip'
        with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr('large.json', 'x' * (assessment.MAX_REPORT_SIZE + 1))
        with self.assertRaisesRegex(ValueError, '크기'):
            assessment.load_reference_report(archive, self.root)

    def test_preview_with_reference_keeps_all_files(self):
        code, out, err = self.command('--reference-report', str(self.ref_path))
        self.assertEqual(code, 0, err)
        self.assertTrue(self.file.exists())
        self.assertIn('ACL에 Everyone', out)
        self.assertIn('[해시 대조] ', out)

    def test_execute_hash_match_really_deletes_temp_file(self):
        token = app.confirmation_token(app.normalize_directory(self.root))
        code, out, err = self.command('--reference-report', str(self.ref_path),
                                      '--execute','--confirm',token)
        self.assertEqual(code, 0, err)
        self.assertFalse(self.file.exists())
        self.assertIn('[DELETED]', out)

    def test_execute_hash_mismatch_blocks_delete(self):
        self.file.write_bytes(b'different data')
        token = app.confirmation_token(app.normalize_directory(self.root))
        code, out, err = self.command('--reference-report', str(self.ref_path),
                                      '--execute','--confirm',token)
        self.assertEqual(code, 1, err)
        self.assertTrue(self.file.exists())
        self.assertIn('SHA-256 불일치', out)
        self.assertIn('FAILED', out)

    def test_execute_no_sha_blocks_delete(self):
        self.ref['files'][0].pop('sha256')
        self.save()
        token = app.confirmation_token(app.normalize_directory(self.root))
        code, out, err = self.command('--reference-report', str(self.ref_path),
                                      '--execute','--confirm',token)
        self.assertEqual(code, 1, err)
        self.assertTrue(self.file.exists())
        self.assertIn('SHA-256이 없어', out)

    def test_reference_validation_prevents_any_file_change(self):
        self.ref['target_dir'] = 'C:\\DifferentFolder'
        self.save()
        token=app.confirmation_token(app.normalize_directory(self.root))
        code, out, err=self.command('--reference-report', str(self.ref_path),
                                   '--execute','--confirm',token)
        self.assertEqual(code, 2)
        self.assertTrue(self.file.exists())
        self.assertIn('대상 폴더', err)

    def test_reference_failed_unlink_still_prints_real_failure(self):
        from unittest.mock import patch
        token=app.confirmation_token(app.normalize_directory(self.root))
        with patch.object(Path,'unlink',side_effect=PermissionError(13,'Access denied')):
            code,out,err=self.command('--reference-report',str(self.ref_path),
                                      '--execute','--confirm',token)
        self.assertEqual(code,1,err)
        self.assertIn('Access denied',out)
        self.assertIn('Everyone: Deny Delete ACL',out)
        self.assertTrue(self.file.exists())

    def test_report_analysis_contains_assessment_and_no_delete(self):
        report_dir = Path(self.tmp.name)/'reports'
        code,out,err=self.command('--analyze-protection','--reference-report',str(self.ref_path),
                                  '--report-dir',str(report_dir))
        self.assertEqual(code,0,err)
        self.assertTrue(self.file.exists())
        loaded=json.loads(next(report_dir.glob('*.json')).read_text('utf-8'))
        self.assertIn('removal_assessment', loaded)
        self.assertIn('reference_hash_match',loaded['removal_assessment']['files'][0])
        self.assertTrue(loaded['removal_assessment']['files'][0]['reference_hash_match'])

if __name__ == '__main__':
    unittest.main()
