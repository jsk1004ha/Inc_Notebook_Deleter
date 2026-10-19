#!/usr/bin/env python3
"""Bulk-delete target files used by the delete_agent batch script.

References:
- https://github.com/ji5zi5/delete_agent (target file names)
- https://github.com/jsk1004ha/Force_deleter (force-delete strategy)
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import json
import locale
import ctypes.wintypes as wintypes
import os
from pathlib import Path
import stat
import time
import subprocess
import sys
import tempfile
import traceback
from dataclasses import dataclass

TARGET_FILES: tuple[str, ...] = (
    "llrxdgfkm.exe",
    "lqndauccd.exe",
    "neagnhoaq.exe",
    "nfowjxyfd.exe",
    "ooajphjh.exe",
    "osurugwgp.exe",
    "qlnsmvsi.exe",
    "qukapttp.exe",
    "rwtyijsa.exe",
    "ryomuigoq.exe",
    "rzzykzbis.exe",
    "tpnvpltow.exe",
    "vfoxujww.exe",
    "ylirkidg.exe",
    "mprogramicon.ico",
)

DEFAULT_TARGET_DIR = Path(r"C:\Windows\SysWOW64")
CCH_RM_SESSION_KEY = 32
ERROR_MORE_DATA = 234
RM_REBOOT_REASON_NONE = 0


@dataclass(frozen=True)
class DeleteResult:
    path: Path
    deleted: bool
    existed_before: bool
    reason: str = ""
    scheduled_for_reboot: bool = False
    dry_run: bool = False


def _ensure_windows() -> None:
    if os.name != "nt":
        raise OSError("Windows 전용 기능입니다. (Restart Manager API 필요)")


def _exists(path_obj: Path) -> bool:
    # Path.exists() ignores dangling links; never resolve a file before
    # checking its type, or a reparse point could redirect the deletion.
    return os.path.lexists(path_obj)


def _error_text(exc: OSError) -> str:
    winerror = getattr(exc, "winerror", None)
    prefix = f"WinError {winerror}" if winerror is not None else f"errno {exc.errno}"
    return f"{prefix}: {exc.strerror or str(exc)}"


def _delete_once(path_obj: Path) -> tuple[bool, str]:
    try:
        mode = path_obj.lstat().st_mode
    except FileNotFoundError:
        return True, ""
    except OSError as exc:
        return False, _error_text(exc)

    # Never recursively remove a directory, symlink, junction, or other
    # filesystem object with a name from the fixed allowlist.
    if not stat.S_ISREG(mode):
        return False, "일반 파일이 아니므로 건너뜀 (디렉터리/링크 삭제 금지)"

    try:
        path_obj.unlink()
    except PermissionError as first_error:
        if os.name != "nt":
            return False, _error_text(first_error)
        # Windows os.chmod only toggles the READONLY file attribute.
        # This does NOT take ownership or change the file's ACL.
        try:
            path_obj.chmod(stat.S_IWRITE)
            path_obj.unlink()
        except OSError as second_error:
            return False, _error_text(second_error)
    except OSError as exc:
        return False, _error_text(exc)

    return (True, "") if not _exists(path_obj) else (False, "삭제 호출 후에도 파일이 존재함")

def _rm_get_locking_pids(path_obj: Path) -> set[int]:
    _ensure_windows()

    class FILETIME(ctypes.Structure):
        _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]

    class RM_UNIQUE_PROCESS(ctypes.Structure):
        _fields_ = [("dwProcessId", wintypes.DWORD), ("ProcessStartTime", FILETIME)]

    class RM_PROCESS_INFO(ctypes.Structure):
        _fields_ = [
            ("Process", RM_UNIQUE_PROCESS),
            ("strAppName", ctypes.c_wchar * 256),
            ("strServiceShortName", ctypes.c_wchar * 64),
            ("ApplicationType", wintypes.DWORD),
            ("AppStatus", wintypes.ULONG),
            ("TSSessionId", wintypes.DWORD),
            ("bRestartable", wintypes.BOOL),
        ]

    rstrtmgr = ctypes.WinDLL("Rstrtmgr.dll")

    rm_start_session = rstrtmgr.RmStartSession
    rm_start_session.argtypes = [ctypes.POINTER(wintypes.DWORD), wintypes.DWORD, wintypes.LPWSTR]
    rm_start_session.restype = wintypes.DWORD

    rm_register_resources = rstrtmgr.RmRegisterResources
    rm_register_resources.argtypes = [
        wintypes.DWORD,
        wintypes.UINT,
        ctypes.POINTER(wintypes.LPCWSTR),
        wintypes.UINT,
        ctypes.c_void_p,
        wintypes.UINT,
        ctypes.c_void_p,
    ]
    rm_register_resources.restype = wintypes.DWORD

    rm_get_list = rstrtmgr.RmGetList
    rm_get_list.argtypes = [
        wintypes.DWORD,
        ctypes.POINTER(wintypes.UINT),
        ctypes.POINTER(wintypes.UINT),
        ctypes.POINTER(RM_PROCESS_INFO),
        ctypes.POINTER(wintypes.DWORD),
    ]
    rm_get_list.restype = wintypes.DWORD

    rm_end_session = rstrtmgr.RmEndSession
    rm_end_session.argtypes = [wintypes.DWORD]
    rm_end_session.restype = wintypes.DWORD

    session_handle = wintypes.DWORD()
    session_key = ctypes.create_unicode_buffer(CCH_RM_SESSION_KEY + 1)
    result = rm_start_session(ctypes.byref(session_handle), 0, session_key)
    if result != 0:
        return set()

    try:
        resource_path = ctypes.c_wchar_p(str(path_obj))
        result = rm_register_resources(session_handle.value, 1, ctypes.byref(resource_path), 0, None, 0, None)
        if result != 0:
            return set()

        proc_info_needed = wintypes.UINT(0)
        proc_info_count = wintypes.UINT(0)
        reboot_reasons = wintypes.DWORD(RM_REBOOT_REASON_NONE)

        result = rm_get_list(
            session_handle.value,
            ctypes.byref(proc_info_needed),
            ctypes.byref(proc_info_count),
            None,
            ctypes.byref(reboot_reasons),
        )

        if result == ERROR_MORE_DATA:
            process_info = (RM_PROCESS_INFO * proc_info_needed.value)()
            proc_info_count = wintypes.UINT(proc_info_needed.value)
            result = rm_get_list(
                session_handle.value,
                ctypes.byref(proc_info_needed),
                ctypes.byref(proc_info_count),
                process_info,
                ctypes.byref(reboot_reasons),
            )
            if result == 0:
                return {int(process_info[i].Process.dwProcessId) for i in range(proc_info_count.value)}
        elif result == 0:
            return set()

        return set()
    finally:
        rm_end_session(session_handle.value)


def _process_image_path(pid: int) -> Path | None:
    """Read only the executable image path; never guess from a PID."""
    _ensure_windows()
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    open_process = kernel32.OpenProcess
    open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    open_process.restype = wintypes.HANDLE
    query_path = kernel32.QueryFullProcessImageNameW
    query_path.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    query_path.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL

    handle = open_process(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        return None
    try:
        buffer = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(buffer))
        if not query_path(handle, 0, buffer, ctypes.byref(size)):
            return None
        return Path(buffer.value)
    finally:
        close_handle(handle)


def _terminate_processes(pids: set[int], target: Path) -> list[str]:
    """Only attempt to stop an executable that is itself the target file.

    Restart Manager also returns unrelated processes that merely opened the
    target (for example Explorer). Terminating those is not safe.
    """
    notes: list[str] = []
    if target.suffix.lower() != ".exe":
        return notes
    current_pid = os.getpid()
    for pid in sorted(pids):
        if pid <= 4 or pid == current_pid:
            continue
        try:
            image = _process_image_path(pid)
        except OSError as exc:
            notes.append(f"PID {pid} 확인 실패: {_error_text(exc)}")
            continue
        if image is None or os.path.normcase(os.path.abspath(image)) != os.path.normcase(os.path.abspath(target)):
            notes.append(f"PID {pid}: 다른 프로세스이므로 종료하지 않음")
            continue
        try:
            completed = subprocess.run(
                ["taskkill", "/PID", str(pid), "/F"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            notes.append(f"PID {pid} 종료 실패: {exc}")
        else:
            if completed.returncode:
                raw = completed.stderr or completed.stdout or b""
                if isinstance(raw, bytes):
                    message = raw.decode(
                        locale.getpreferredencoding(False), errors="replace"
                    ).strip()
                else:
                    message = str(raw).strip()
                message = " ".join(message.split())[:350]
                detail = f": {message}" if message else ""
                notes.append(
                    f"PID {pid}: taskkill 종료 코드 {completed.returncode}{detail}"
                )
    return notes


def _schedule_delete_on_reboot(target: Path) -> tuple[bool, str]:
    """Request deletion at next boot; success here is NOT deletion now."""
    _ensure_windows()
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    move_file = kernel32.MoveFileExW
    move_file.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    move_file.restype = wintypes.BOOL
    if move_file(str(target), None, 0x00000004):  # MOVEFILE_DELAY_UNTIL_REBOOT
        return True, ""
    return False, f"재부팅 삭제 예약 실패 (WinError {ctypes.get_last_error()})"


def _force_delete_with_reason(
    path_to_folder_or_file: os.PathLike[str] | str,
    retries: int = 3,
    dry_run: bool = False,
    schedule_reboot: bool = False,
) -> tuple[bool, str, bool]:
    # absolute() does not follow a final-component symlink; resolve() does.
    target = Path(path_to_folder_or_file).expanduser().absolute()
    if not _exists(target):
        return True, "", False

    try:
        if not stat.S_ISREG(target.lstat().st_mode):
            return False, "일반 파일이 아니므로 삭제하지 않음 (디렉터리/링크 보호)", False
    except OSError as exc:
        return False, _error_text(exc), False

    if dry_run:
        return False, "삭제 예정 (dry-run)", False

    deleted, reason = _delete_once(target)
    if deleted:
        return True, "", False
    if os.name == "nt":
        notes: list[str] = []
        attempted_pids: set[int] = set()
        for _ in range(max(0, retries)):
            try:
                locking_pids = _rm_get_locking_pids(target)
                fresh_pids = locking_pids - attempted_pids
                attempted_pids.update(fresh_pids)
                if fresh_pids:
                    notes.extend(_terminate_processes(fresh_pids, target))
            except OSError as exc:
                notes.append(f"잠금 조회 실패: {_error_text(exc)}")
            time.sleep(0.2)
            deleted, reason = _delete_once(target)
            if deleted:
                return True, "", False

        if schedule_reboot:
            scheduled, schedule_error = _schedule_delete_on_reboot(target)
            if scheduled:
                return False, "재부팅 시 삭제 예약됨 (아직 파일 존재)", True
            notes.append(schedule_error)
        if notes:
            reason += " | " + "; ".join(notes[-3:])
    return False, reason, False


def force_delete_file_folder(
    path_to_folder_or_file: os.PathLike[str] | str,
    retries: int = 3,
    dry_run: bool = False,
) -> bool:
    """Backward-compatible boolean API. Use delete_targets for diagnostics."""
    deleted, _, _ = _force_delete_with_reason(path_to_folder_or_file, retries, dry_run)
    return deleted

def delete_targets(
    target_dir: Path,
    retries: int,
    dry_run: bool = False,
    schedule_reboot: bool = False,
) -> list[DeleteResult]:
    results: list[DeleteResult] = []
    for file_name in TARGET_FILES:
        target_path = target_dir / file_name
        existed_before = _exists(target_path)
        deleted, reason, scheduled = _force_delete_with_reason(
            target_path,
            retries=retries,
            dry_run=dry_run,
            schedule_reboot=schedule_reboot,
        )
        results.append(
            DeleteResult(
                path=target_path,
                deleted=deleted,
                existed_before=existed_before,
                reason=reason,
                scheduled_for_reboot=scheduled,
                dry_run=dry_run and existed_before,
            )
        )
    return results


def _is_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (OSError, AttributeError):
        return False


def _is_in_windows_directory(path: Path) -> bool:
    if os.name != "nt":
        return False
    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    return path.resolve(strict=False).is_relative_to(system_root.resolve(strict=False))

def _file_sha256(path: Path) -> str:
    """Stream a file for incident triage; never copy or modify it."""
    digest = hashlib.sha256()
    with path.open("rb") as infile:
        while True:
            block = infile.read(256 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _read_file_identity(path: Path) -> tuple[dict[str, str], str]:
    """Read signature, version metadata, and owner; no file changes.

    PowerShell outputs base64 UTF-8 JSON to avoid legacy console encoding
    failures and receives the path via an environment variable to avoid
    command injection when diagnosing unusual filenames.
    """
    if os.name != "nt":
        return {}, "Windows 전용 서명 및 소유권 조회"

    ps_code = r"""
$ErrorActionPreference = 'Stop'
$p = $env:INC_TARGET_PATH
$signature = Get-AuthenticodeSignature -LiteralPath $p
$item = Get-Item -LiteralPath $p
$owner = ''
try { $owner = (Get-Acl -LiteralPath $p -ErrorAction Stop).Owner }
catch { $owner = '(access denied)' }
$data = [ordered]@{
    Signature = [string]$signature.Status
    Signer = $(if ($null -ne $signature.SignerCertificate) {
        [string]$signature.SignerCertificate.Subject
    } else { '(unsigned)' })
    Company = [string]$item.VersionInfo.CompanyName
    Description = [string]$item.VersionInfo.FileDescription
    Version = [string]$item.VersionInfo.FileVersion
    Owner = $owner
}
$json = $data | ConvertTo-Json -Compress
[Console]::WriteLine([Convert]::ToBase64String(
    [Text.Encoding]::UTF8.GetBytes($json)))
"""
    env = dict(os.environ)
    env["INC_TARGET_PATH"] = str(path)
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps_code],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {}, f"서명 조회 실패: {exc}"
    if proc.returncode:
        return {}, f"서명 조회 실패 (PowerShell exit {proc.returncode})"
    try:
        encoded = proc.stdout.decode("ascii").strip().splitlines()[-1]
        metadata = json.loads(base64.b64decode(encoded, validate=True).decode("utf-8"))
        return {str(k): str(value) for k, value in metadata.items()}, ""
    except (ValueError, IndexError, UnicodeError, TypeError) as exc:
        return {}, f"서명 메타데이터 해석 실패: {exc}"


def _read_file_acl(path: Path) -> tuple[str, str]:
    if os.name != "nt":
        return "", "Windows 전용 ACL 조회"
    try:
        proc = subprocess.run(
            ["icacls", str(path)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return "", f"ACL 조회 실패: {exc}"
    preferred = locale.getpreferredencoding(False)
    message = (proc.stdout if proc.returncode == 0 else proc.stderr).decode(
        preferred, errors="replace"
    ).strip()
    if proc.returncode:
        return "", f"icacls exit {proc.returncode}: {message[:300]}"
    return message[:2000], ""


def inspect_protection(target_dir: Path) -> int:
    """Read-only evidence collection for access denied or suspected tampering."""
    print("=" * 56)
    print("[파일 보호 진단] 파일 삭제/프로세스 종료/권한 변경 없음")
    print(f"대상 디렉터리: {target_dir}")
    print(f"관리자 권한: {'있음' if _is_admin() else '없음'}")
    print("=" * 56)
    found = 0

    for name in TARGET_FILES:
        path = target_dir / name
        if not _exists(path):
            continue
        found += 1
        print(f"\n[발견] {name}")
        try:
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode):
                print("  종류: 일반 파일이 아님 (링크·폴더 의심, 검사 건너뜀)")
                continue
            print(f"  크기: {info.st_size} bytes")
            if hasattr(info, "st_file_attributes"):
                print(f"  파일 특성: 0x{info.st_file_attributes:08X}")
        except OSError as exc:
            print(f"  파일 정보 조회 실패: {_error_text(exc)}")
            continue

        try:
            print(f"  SHA256: {_file_sha256(path)}")
        except OSError as exc:
            print(f"  SHA256 조회 실패: {_error_text(exc)}")

        metadata, error = _read_file_identity(path)
        if error:
            print(f"  {error}")
        else:
            for key, value in metadata.items():
                print(f"  {key}: {value or '(unknown)'}")

        acl, acl_error = _read_file_acl(path)
        if acl_error:
            print(f"  {acl_error}")
        elif acl:
            print("  접근 제어 목록 (읽기 전용):")
            for line in acl.splitlines()[:12]:
                print(f"    {line}")

        if os.name == "nt":
            try:
                pids = _rm_get_locking_pids(path)
                if not pids:
                    print("  Restart Manager: 잠금 프로세스 보고 없음")
                for pid in sorted(pids)[:16]:
                    process_path = _process_image_path(pid)
                    print(f"  잠금 프로세스 PID {pid}: {process_path or '(경로 조회 불가)'}")
            except OSError as exc:
                print(f"  Restart Manager 조회 실패: {_error_text(exc)}")
    print("\n" + "=" * 56)
    print(f"발견한 파일: {found}/{len(TARGET_FILES)}")
    print("참고: 미서명 또는 WinError 5만으로 악성 여부가 확정되지는 않습니다.")
    print("진단만 수행했으며 파일, 프로세스 및 권한을 변경하지 않았습니다.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bulk-delete-agent-targets",
        description="미리 지정된 파일 목록을 검사하고 삭제합니다.",
    )
    parser.add_argument(
        "--target-dir",
        type=Path,
        default=DEFAULT_TARGET_DIR,
        help=f"대상 디렉터리 (기본값: {DEFAULT_TARGET_DIR})",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=3,
        help="잠금 프로세스 검사 후 재시도 횟수 (기본값: 3)",
    )
    parser.add_argument("--dry-run", action="store_true", help="실제 삭제 없이 대상 확인")
    parser.add_argument("--diagnose", action="store_true", help="실행 환경 확인. 삭제하지 않음")
    parser.add_argument(
        "--inspect-protection",
        action="store_true",
        help="발견된 파일의 SHA256, 서명, 소유권, ACL, 잠금 PID 확인 (읽기 전용)",
    )
    parser.add_argument("--mode", choices=("check", "delete"), default="delete",
                        help="check는 확인만 수행, delete는 삭제 시도")
    parser.add_argument(
        "--schedule-reboot",
        action="store_true",
        help="즉시 삭제할 수 없는 파일을 다음 재부팅 때 삭제하도록 예약 (Windows 관리자 권한 필요)",
    )
    return parser


def _run_cli(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    target_dir = args.target_dir.expanduser().resolve(strict=False)
    if args.inspect_protection:
        return inspect_protection(target_dir)
    check_only = args.dry_run or args.diagnose or args.mode == "check"
    if args.diagnose:
        print("[진단 모드] 파일 삭제 및 프로세스 종료를 수행하지 않습니다.")
        print(f"Python: {sys.version.split()[0]}, 패키징된 EXE: {bool(getattr(sys, 'frozen', False))}")
        print(f"실행 경로: {sys.executable}")
        print(f"관리자 권한: {'있음' if _is_admin() else '없음'}")
    else:
        print(f"[시작] 모드: {'검사' if check_only else '삭제'}")
    sys.stdout.flush()

    if _is_in_windows_directory(target_dir) and not check_only and not _is_admin():
        print("[오류] Windows 시스템 디렉터리에는 관리자 권한이 필요합니다.")
        print("       관리자 권한으로 CMD/PowerShell을 실행한 후 Python 스크립트를 실행하세요.")
        print("       실제 삭제 시에는 관리자의 승인이 필요합니다.")
        return 2

    results = delete_targets(
        target_dir=target_dir,
        retries=max(0, args.retries),
        dry_run=check_only,
        schedule_reboot=args.schedule_reboot and not check_only,
    )
    deleted_count = 0
    missing_count = 0
    failed_count = 0
    scheduled_count = 0
    dry_count = 0

    print("=" * 56)
    print(f"대상 디렉터리: {target_dir}")
    print("=" * 56)
    for item in results:
        if not item.existed_before:
            print(f"[없음] {item.path.name}")
            missing_count += 1
        elif item.dry_run and item.reason.startswith("삭제 예정"):
            print(f"[예정] {item.path.name} - 삭제하지 않음")
            dry_count += 1
        elif item.deleted:
            print(f"[삭제됨] {item.path.name}")
            deleted_count += 1
        elif item.scheduled_for_reboot:
            print(f"[예약됨] {item.path.name} - {item.reason}")
            scheduled_count += 1
        else:
            print(f"[실패] {item.path.name} - {item.reason}")
            failed_count += 1
    print("=" * 56)
    print(
        f"삭제 성공: {deleted_count}, 기존 없음: {missing_count}, "
        f"삭제 예정(dry-run): {dry_count}, 재부팅 예약: {scheduled_count}, 실패: {failed_count}"
    )
    print("=" * 56)
    if failed_count:
        return 1
    if scheduled_count:
        return 3
    return 0

def _select_arguments(argv: list[str] | None) -> tuple[list[str], bool]:
    options = list(sys.argv[1:] if argv is None else argv)
    if options:
        return options, False
    if sys.stdin is None or not sys.stdin.isatty():
        return ["--diagnose"], False
    print("Inc Notebook Deleter")
    print("1. 실행 환경 및 파일 검사 (삭제 없음)")
    print("2. 파일 삭제 (관리자 승인 필요)")
    print("0. 종료")
    try:
        choice = input("번호 선택 [기본 1]: ").strip() or "1"
    except (EOFError, KeyboardInterrupt):
        return ["--diagnose"], True
    if choice == "2":
        try:
            answer = input("실제 삭제하려면 DELETE를 입력: ").strip()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        if answer == "DELETE":
            return ["--mode", "delete"], True
        print("삭제 취소: 진단 모드로 전환합니다.")
    if choice == "0":
        return ["--diagnose"], True
    return ["--diagnose"], True


def main(argv: list[str] | None = None) -> int:
    options, interactive = _select_arguments(argv)
    try:
        return _run_cli(options)
    finally:
        if interactive:
            try:
                input("\n결과를 확인한 뒤 Enter를 눌러 닫으세요...")
            except (EOFError, KeyboardInterrupt):
                pass


def _configure_console_encoding() -> None:
    """Avoid UnicodeEncodeError on Windows terminals using CP1252/legacy encodings.

    Text written to a redirected diagnostics file should also be UTF-8.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="backslashreplace")
        except (OSError, ValueError, TypeError):
            pass


def _entrypoint() -> int:
    try:
        return main()
    except Exception:
        details = traceback.format_exc()
        print(f"[실행 오류]\n{details}", file=sys.stderr)
        log = Path(tempfile.gettempdir()) / "inc-notebook-deleter-error.log"
        try:
            log.write_text(details, encoding="utf-8")
            print(f"오류 로그: {log}", file=sys.stderr)
        except OSError:
            pass
        if sys.stdin is not None and sys.stdin.isatty():
            try:
                input("Enter를 눌러 닫으세요...")
            except (EOFError, KeyboardInterrupt):
                pass
        return 10


if __name__ == "__main__":
    _configure_console_encoding()
    raise SystemExit(_entrypoint())
