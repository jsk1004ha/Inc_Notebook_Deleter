"""Evidence-based, read-only assessment of file deletion blockers.

Does not modify DACLs, owners, running services, or security software.
User-supplied JSON/ZIP reports are treated as untrusted diagnostic data.
"""
from __future__ import annotations

import json
import ntpath
from pathlib import Path
import re
import zipfile

TARGETS = frozenset(("lqndauccd.exe", "ooajphjh.exe", "qukapttp.exe", "rwtyijsa.exe"))
MAX_REPORT_SIZE = 2 * 1024 * 1024
MAX_REPORT_COUNT = 20
MAX_ARCHIVE_SIZE = 10 * 1024 * 1024
_HEX_64 = re.compile(r"^[a-fA-F0-9]{64}$")


def _path_key(path: object) -> str:
    return ntpath.normcase(ntpath.normpath(str(path)))


def _validate_report(obj: object, expected_target_dir: Path | None) -> dict:
    if not isinstance(obj, dict):
        raise ValueError("참조 보고서의 최상위 구조가 JSON 객체가 아닙니다")
    if obj.get('schema_version') != 1:
        raise ValueError("지원하지 않는 보고서 schema_version")
    directory = obj.get('target_dir')
    if not isinstance(directory, str) or not directory:
        raise ValueError("보고서에 target_dir이 없습니다")
    if expected_target_dir is not None and _path_key(directory) != _path_key(expected_target_dir):
        raise ValueError("참조 보고서의 대상 폴더가 현재 실행 대상과 다릅니다")
    rows = obj.get('files')
    if not isinstance(rows, list) or len(rows) > 50:
        raise ValueError("보고서 files 배열이 유효하지 않습니다")
    names: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get('name'), str):
            raise ValueError("보고서의 파일 항목이 잘못되었습니다")
        name = row['name'].casefold()
        if name not in TARGETS or name in names:
            raise ValueError("보고서에 승인 범위 밖 또는 중복된 파일이 있습니다")
        names.add(name)
        if 'sha256' in row and not _HEX_64.fullmatch(str(row['sha256'])):
            raise ValueError("보고서 SHA-256 형식이 올바르지 않습니다")
    if not isinstance(obj.get('windows_data'), dict):
        raise ValueError("보고서에 windows_data 객체가 없습니다")
    return obj


def load_reference_report(path: Path, target_dir: Path | None = None) -> dict:
    """Load an earlier JSON report or ZIP containing reports, without extracting.

    Select the report with the latest ISO-8601 capture timestamp. Imported
    reports provide *historical evidence*, not a claim about current machine state.
    """
    source = Path(path)
    if not source.is_file() or source.is_symlink():
        raise ValueError("참조 보고서 파일이 없거나 심볼릭 링크입니다")
    if source.stat().st_size > MAX_ARCHIVE_SIZE:
        raise ValueError("참조 보고서 크기 제한(10 MiB)을 초과했습니다")
    reports: list[dict] = []
    if source.suffix.casefold() == '.zip':
        try:
            with zipfile.ZipFile(source) as archive:
                candidates = [item for item in archive.infolist()
                              if not item.is_dir() and item.filename.lower().endswith('.json')]
                if not candidates or len(candidates) > MAX_REPORT_COUNT:
                    raise ValueError("ZIP에는 1~20개의 JSON 보고서가 있어야 합니다")
                for item in candidates:
                    if item.file_size > MAX_REPORT_SIZE:
                        raise ValueError("압축된 JSON 보고서의 크기가 너무 큽니다")
                    with archive.open(item) as file:
                        raw = file.read(MAX_REPORT_SIZE + 1)
                    if len(raw) > MAX_REPORT_SIZE:
                        raise ValueError("ZIP 보고서 압축 해제 크기 제한 초과")
                    reports.append(_validate_report(json.loads(raw.decode('utf-8-sig')), target_dir))
        except (zipfile.BadZipFile, RuntimeError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"ZIP 참조 보고서를 읽을 수 없습니다: {exc}") from exc
    elif source.suffix.casefold() == '.json':
        if source.stat().st_size > MAX_REPORT_SIZE:
            raise ValueError("JSON 보고서의 크기가 너무 큽니다")
        try:
            reports.append(_validate_report(json.loads(source.read_text(encoding='utf-8-sig')), target_dir))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"JSON 참조 보고서를 읽을 수 없습니다: {exc}") from exc
    else:
        raise ValueError("참조 보고서는 .json 또는 .zip만 지원합니다")
    return max(reports, key=lambda d: str(d.get('captured_utc', '')))


def _is_delete_deny(rule: dict) -> bool:
    if str(rule.get('type', '')).casefold() != 'deny':
        return False
    principal = str(rule.get('principal', '')).casefold().strip()
    # Everyone's well-known SID is S-1-1-0. Do not infer principal from 'Users'.
    if principal not in {'everyone', 's-1-1-0', '모든 사용자'}:
        return False
    rights = re.split(r'[,| ]+', str(rule.get('rights', '')).casefold())
    return any(right in {'delete', 'fullcontrol'} for right in rights)


def _file_summary(name: str, report: dict) -> dict:
    rows = report.get('files') or []
    row = next((r for r in rows if isinstance(r, dict) and str(r.get('name', '')).casefold() == name), {})
    windows = report.get('windows_data') or {}
    metadata = next((r for r in windows.get('targets', [])
                     if isinstance(r, dict) and str(r.get('name', '')).casefold() == name), {})
    acl = metadata.get('acl') or {}
    rules = acl.get('rules') or []
    deny = any(isinstance(r, dict) and _is_delete_deny(r) for r in rules)
    services = []
    for service in windows.get('services', []) or []:
        if not isinstance(service, dict):
            continue
        service_path = str(service.get('path') or '').casefold()
        # Only record an exact file-name component, not an arbitrary substring.
        if re.search(r'(?:^|[\\/])' + re.escape(name) + r'(?:$|[" ]|[\t])', service_path):
            services.append({
                'name': str(service.get('name') or ''),
                'state': str(service.get('state') or ''),
                'account': str(service.get('account') or ''),
                'start_mode': str(service.get('start_mode') or ''),
                'pid': service.get('pid'),
            })
    processes = []
    for process in windows.get('processes', []) or []:
        if isinstance(process, dict) and str(process.get('name') or '').casefold() == name:
            processes.append({'pid': process.get('pid'), 'name': str(process.get('name'))})
    reasons = []
    if deny:
        reasons.append('ACL에 Everyone의 명시적 Delete 거부 규칙이 있음')
    if services:
        reasons.append('해당 파일과 연결된 Windows 서비스: ' + ', '.join(s['name'] for s in services))
    if processes:
        reasons.append('실행 중인 프로세스: ' + ', '.join(str(p['pid']) for p in processes))
    owner = str(metadata.get('owner') or '')
    if owner.casefold() in {'nt authority\\system', 'system'}:
        reasons.append('소유자: NT AUTHORITY\\SYSTEM')
    state = str(row.get('state') or 'unknown')
    if state == 'missing':
        classification = 'already_absent'
    elif deny:
        classification = 'acl_restriction'
    elif services:
        classification = 'service_in_use'
    elif state != 'regular':
        classification = 'unknown'
    else:
        classification = 'no_specific_blocker_identified'
    return {
        'name': name,
        'state': state,
        'classification': classification,
        'acl_explicit_everyone_delete_deny': deny,
        'owner': owner,
        'running_services': services,
        'matched_processes': processes,
        'sha256': str(row.get('sha256') or '').lower(),
        'reasons': reasons,
    }


def assess_report(live_report: dict, baseline: dict | None = None) -> dict:
    """Summarize known restrictions; never claims successful removal."""
    details = []
    old = {entry['name'].casefold(): entry for entry in baseline.get('files', [])} if baseline else {}
    for name in sorted(TARGETS):
        item = _file_summary(name, live_report)
        if baseline is not None:
            past = old.get(name, {})
            expected = str(past.get('sha256') or '').casefold()
            actual = item['sha256']
            if expected and actual:
                match = expected == actual
            else:
                match = None
            item['reference_sha256'] = expected
            item['reference_hash_match'] = match
            if match is False:
                item['classification'] = 'file_changed_since_reference'
                item['reasons'].insert(0, '참조 보고서와 SHA-256 불일치: 파일 동일성 재확인 필요')
        details.append(item)
    findings = {
        'acl_deny_count': sum(x['acl_explicit_everyone_delete_deny'] for x in details),
        'matched_running_service_count': sum(
            (s['state'].casefold() == 'running') for x in details for s in x['running_services']
        ),
        'changed_hash_count': sum(x.get('reference_hash_match') is False for x in details),
        'admin': bool(live_report.get('admin', False)),
        'files': details,
        'note': (
            'ACL 거부 규칙은 기존 접근 실패와 부합하지만, 해당 규칙만으로 모든'
            ' 실패의 원인이 확정되는 것은 아닙니다. 서비스/드라이버를 중단하거나'
            ' 권한을 변경하지 않았습니다. 참조 보고서는 이전 시점의 증거입니다.'
        ),
    }
    return findings


def format_assessment(assessment: dict) -> str:
    lines = [
        '=== 삭제 가능성 및 보호 상태 평가 (읽기 전용) ===',
        f"관리자 권한: {'있음' if assessment['admin'] else '없음'}",
        f"명시적 Everyone Delete 거부: {assessment['acl_deny_count']}개",
        f"실행 중인 연결 서비스: {assessment['matched_running_service_count']}개",
    ]
    for row in assessment['files']:
        lines.append(f"[{row['name']}] {row['classification']}")
        for reason in row['reasons']:
            lines.append('  - ' + reason)
        if 'reference_hash_match' in row:
            lines.append(f"  - 참조 해시와 비교: {row['reference_hash_match']}")
    lines.append(assessment['note'])
    return '\n'.join(lines)


def baseline_hashes(baseline: dict) -> dict[str, str]:
    return {str(r['name']).casefold(): str(r['sha256']).casefold()
            for r in baseline.get('files', [])
            if isinstance(r, dict) and r.get('sha256')}


def describe_known_access_denial(name: str, baseline: dict | None) -> str:
    if baseline is None:
        return ''
    detail = _file_summary(name.casefold(), baseline)
    if detail['acl_explicit_everyone_delete_deny']:
        return '참조 보고서에서 Everyone: Deny Delete ACL이 확인됨(현재 상태는 재조회 필요)'
    return ''
