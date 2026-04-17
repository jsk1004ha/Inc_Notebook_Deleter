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
import shutil
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


def _ensure_windows() -> None:
    if os.name != "nt":
        raise OSError("Windows 전용 기능입니다. (Restart Manager API 필요)")


def _delete_once(path_obj: Path) -> bool:
    if not path_obj.exists():
        return True
    try:
        if path_obj.is_dir():
            shutil.rmtree(path_obj)
        else:
            path_obj.unlink()
    except OSError:
        return False
    return not path_obj.exists()


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


def _terminate_processes(pids: set[int], dry_run: bool = False) -> None:
    current_pid = os.getpid()
    for pid in sorted(pids):
        if pid <= 0 or pid == current_pid:
            continue
        if dry_run:
            print(f"[DRY-RUN] taskkill /PID {pid} /F /T")
            continue
        subprocess.run(
            ["taskkill", "/PID", str(pid), "/F", "/T"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def force_delete_file_folder(path_to_folder_or_file: os.PathLike[str] | str, retries: int = 3, dry_run: bool = False) -> bool:
    target = Path(path_to_folder_or_file).expanduser().resolve(strict=False)

    if not target.exists():
        return True

    if dry_run:
        print(f"[DRY-RUN] 삭제 시도: {target}")
        return False

    if _delete_once(target):
        return True

    if os.name != "nt":
        return False

    for _ in range(max(0, retries)):
        locking_pids = _rm_get_locking_pids(target)
        if locking_pids:
            _terminate_processes(locking_pids)
        if _delete_once(target):
            return True
    return False


def delete_targets(target_dir: Path, retries: int, dry_run: bool = False) -> list[DeleteResult]:
    results: list[DeleteResult] = []
    for file_name in TARGET_FILES:
        target_path = target_dir / file_name
        existed_before = target_path.exists()
        deleted = force_delete_file_folder(target_path, retries=retries, dry_run=dry_run)
        results.append(DeleteResult(path=target_path, deleted=deleted, existed_before=existed_before))
    return results


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bulk-delete-agent-targets",
        description="delete_agent 대상 파일들을 한 번에 강제 삭제합니다.",
    )
    parser.add_argument(
        "--target-dir",
        type=Path,
        default=DEFAULT_TARGET_DIR,
        help=f"삭제 대상 디렉터리 (기본값: {DEFAULT_TARGET_DIR})",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=3,
        help="잠금 프로세스 종료 후 재시도 횟수 (기본값: 3)",
    )
    parser.add_argument("--dry-run", action="store_true", help="실제 삭제 없이 작업 계획만 출력")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    target_dir = args.target_dir.expanduser().resolve(strict=False)
    results = delete_targets(target_dir=target_dir, retries=max(0, args.retries), dry_run=args.dry_run)

    deleted_count = 0
    missing_count = 0
    failed_count = 0

    print("=" * 56)
    print(f"대상 디렉터리: {target_dir}")
    print("=" * 56)

    for item in results:
        if not item.existed_before:
            print(f"[없음] {item.path.name}")
            missing_count += 1
            continue
        if item.deleted:
            print(f"[삭제됨] {item.path.name}")
            deleted_count += 1
        else:
            print(f"[실패] {item.path.name}")
            failed_count += 1

    print("=" * 56)
    print(f"삭제 성공: {deleted_count}, 기존 없음: {missing_count}, 실패: {failed_count}")
    print("=" * 56)

    if failed_count:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
