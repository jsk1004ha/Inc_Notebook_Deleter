#!/usr/bin/env python3
"""Bulk-delete target files used by the delete_agent batch script.

References:
- https://github.com/ji5zi5/delete_agent (target file names)
- https://github.com/jsk1004ha/Force_deleter (force-delete strategy)
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wintypes
import os
from pathlib import Path
import stat
import time
import subprocess
import sys
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
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            notes.append(f"PID {pid} 종료 실패: {exc}")
        else:
            if completed.returncode:
                notes.append(f"PID {pid}: taskkill 종료 코드 {completed.returncode}")
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
        for _ in range(max(0, retries)):
            try:
                locking_pids = _rm_get_locking_pids(target)
                if locking_pids:
                    notes.extend(_terminate_processes(locking_pids, target))
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
    parser.add_argument(
        "--schedule-reboot",
        action="store_true",
        help="즉시 삭제할 수 없는 파일을 다음 재부팅 때 삭제하도록 예약 (Windows 관리자 권한 필요)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    target_dir = args.target_dir.expanduser().resolve(strict=False)

    if _is_in_windows_directory(target_dir) and not args.dry_run and not _is_admin():
        print("[오류] Windows 시스템 디렉터리에는 관리자 권한이 필요합니다.")
        print("       관리자 권한으로 CMD/PowerShell을 실행한 후 Python 스크립트를 실행하세요.")
        print("       빌드된 EXE는 UAC 권한 요청을 표시합니다.")
        return 2

    results = delete_targets(
        target_dir=target_dir,
        retries=max(0, args.retries),
        dry_run=args.dry_run,
        schedule_reboot=args.schedule_reboot,
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

if __name__ == "__main__":
    raise SystemExit(main())
