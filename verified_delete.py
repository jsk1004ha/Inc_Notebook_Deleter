#!/usr/bin/env python3
"""Audited deletion of four explicitly scoped files; never bypasses OS protection."""
from __future__ import annotations

import argparse
import ctypes
import binascii
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
from datetime import datetime, timezone
import removal_assessment as evidence

# Exact four files the user identified as remaining after the previous run.
TARGETS = ("lqndauccd.exe", "ooajphjh.exe", "qukapttp.exe", "rwtyijsa.exe")
DEFAULT_DIR = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "SysWOW64"
REPARSE_POINT = 0x400
RETRY_WINERRORS = {32, 33}  # Sharing violation and lock violation, not access denied.


def normalize_directory(path: Path) -> Path:
    if ".." in path.parts:
        raise ValueError("상위 경로(..)를 사용한 디렉터리 지정은 허용하지 않습니다")
    if os.name == "nt" and str(path).startswith(("\\\\", "//")):
        raise ValueError("네트워크/UNC 경로는 지원하지 않습니다")
    folder = Path(os.path.abspath(os.path.expanduser(str(path))))
    if folder == folder.parent:
        raise ValueError("드라이브 또는 파일시스템 루트는 지정할 수 없습니다")
    for candidate in (folder, *folder.parents):
        try:
            info = candidate.lstat()
        except OSError as exc:
            raise ValueError(f"디렉터리를 확인할 수 없습니다: {candidate}: {exc}") from exc
        if stat.S_ISLNK(info.st_mode) or (getattr(info, "st_file_attributes", 0) & REPARSE_POINT):
            raise ValueError(f"심볼릭 링크 또는 재분석 지점을 통과할 수 없습니다: {candidate}")
    if not folder.is_dir():
        raise ValueError(f"디렉터리가 아닙니다: {folder}")
    return folder


def confirmation_token(folder: Path) -> str:
    key = os.path.normcase(str(folder)) + "|" + "|".join(TARGETS)
    return "DELETE-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:12].upper()


def is_admin() -> bool:
    if os.name != "nt":
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (OSError, AttributeError):
        return False


def is_windows_system_dir(folder: Path) -> bool:
    if os.name != "nt":
        return False
    system_root = os.path.normcase(os.path.abspath(os.environ.get("SystemRoot", r"C:\Windows")))
    try:
        return os.path.commonpath([system_root, os.path.normcase(str(folder))]) == system_root
    except ValueError:  # Different Windows drive letters.
        return False


def current_state(path: Path) -> str:
    """Return missing, regular, or unsafe. Never follow the final path component."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return "missing"
    except OSError as exc:
        return f"error: {exc}"
    if stat.S_ISLNK(info.st_mode) or (getattr(info, "st_file_attributes", 0) & REPARSE_POINT):
        return "unsafe: symbolic link/reparse point"
    if not stat.S_ISREG(info.st_mode):
        return "unsafe: not a regular file"
    return "regular"


def error_details(exc: OSError) -> str:
    code = getattr(exc, "winerror", None)
    return f"WinError {code}: {exc}" if code is not None else f"errno {exc.errno}: {exc}"


def remove_and_verify(path: Path, folder: Path) -> tuple[str, str]:
    """Actually invoke Windows/POSIX file deletion and verify absence."""
    if path.parent != folder or path.name not in TARGETS:
        return "failed", "승인된 디렉터리/파일명 범위를 벗어남"
    for attempt in range(3):
        # Re-check the parent and file before every attempt.
        try:
            normalize_directory(folder)
        except ValueError as exc:
            return "failed", str(exc)
        state = current_state(path)
        if state == "missing":
            return ("missing" if attempt == 0 else "failed"), "삭제 전/중 파일이 없어짐"
        if state != "regular":
            return "failed", state
        try:
            path.unlink()  # Real filesystem deletion. No simulation or ACL bypass.
        except OSError as exc:
            code = getattr(exc, "winerror", None)
            if code in RETRY_WINERRORS and attempt < 2:
                time.sleep(0.3)
                continue
            return "failed", error_details(exc)
        state_after = current_state(path)
        if state_after == "missing":
            return "deleted", "삭제 후 부재 확인"
        return "failed", f"삭제 호출 후 재검사 결과: {state_after}"
    return "failed", "재시도 횟수 초과"


def log_record(log_file, *, mode: str, path: Path, status: str, detail: str) -> None:
    record = {
        "time_utc": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "path": str(path),
        "status": status,
        "detail": detail,
    }
    log_file.write(json.dumps(record, ensure_ascii=False) + "\n")
    log_file.flush()


# All diagnostic probes are read-only.  PowerShell receives all user-provided
# paths through environment variables, not string interpolation.
_WINDOWS_PROBE = r'''
$ErrorActionPreference = 'Stop'
$root = $env:INC_NOTEBOOK_TARGET_DIR
$targets = @((ConvertFrom-Json -InputObject $env:INC_NOTEBOOK_TARGETS_JSON))
$hints = @('JNESS', 'Momi', 'DSesSvc', '유해차단')
$indicators = @($targets) + $hints
$report = [ordered]@{
  targets = @(); processes = @(); services = @(); drivers = @();
  scheduled_tasks = @(); startup_entries = @(); events = @(); errors = @();
  defender = $null
}
function IsRelevant([object]$value) {
  if ($null -eq $value) { return $false }
  $s = [string]$value
  foreach ($needle in $indicators) {
    if ($s.IndexOf([string]$needle, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
      return $true
    }
  }
  return $false
}
function AppendError([string]$area, [object]$err) {
  $report.errors += ($area + ': ' + [string]$err)
}
foreach ($name in $targets) {
  $path = Join-Path $root ([string]$name)
  $row = [ordered]@{
    name = [string]$name; path = [string]$path;
    owner = $null; acl = $null; signature = $null;
    company = $null; product = $null; description = $null;
    file_version = $null; error = $null
  }
  try {
    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if ($item.PSIsContainer) { $row.error = 'Directory is not a regular file' }
    else {
      $info = $item.VersionInfo
      $row.company = [string]$info.CompanyName
      $row.product = [string]$info.ProductName
      $row.description = [string]$info.FileDescription
      $row.file_version = [string]$info.FileVersion
      try {
        $sig = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
        $subject = $null
        $thumb = $null
        if ($null -ne $sig.SignerCertificate) {
          $subject = [string]$sig.SignerCertificate.Subject
          $thumb = [string]$sig.SignerCertificate.Thumbprint
        }
        $row.signature = @{status = [string]$sig.Status;
                           signer_subject = $subject; thumbprint = $thumb}
      } catch { AppendError ('signature/' + $name) $_.Exception.Message }
      try {
        $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
        $row.owner = [string]$acl.Owner
        $rules = @()
        foreach ($rule in @($acl.Access | Select-Object -First 48)) {
          $rules += @{
            principal = [string]$rule.IdentityReference;
            type = [string]$rule.AccessControlType;
            rights = [string]$rule.FileSystemRights;
            inherited = [bool]$rule.IsInherited
          }
        }
        $row.acl = @{protected = [bool]$acl.AreAccessRulesProtected; rules = @($rules)}
      } catch { AppendError ('acl/' + $name) $_.Exception.Message }
    }
  } catch [System.Management.Automation.ItemNotFoundException] {
    $row.error = 'Not found'
  } catch {
    $row.error = [string]$_.Exception.Message
    AppendError ('file/' + $name) $_.Exception.Message
  }
  $report.targets += $row
}
try {
  foreach ($proc in @(Get-CimInstance Win32_Process -ErrorAction Stop)) {
    if (IsRelevant ($proc.Name + ' ' + $proc.ExecutablePath)) {
      $report.processes += @{
        name = [string]$proc.Name; pid = [int]$proc.ProcessId;
        parent_pid = [int]$proc.ParentProcessId;
        executable_path = [string]$proc.ExecutablePath
      }
    }
  }
} catch { AppendError 'processes' $_.Exception.Message }
try {
  foreach ($svc in @(Get-CimInstance Win32_Service -ErrorAction Stop)) {
    if (IsRelevant ($svc.Name + ' ' + $svc.DisplayName + ' ' + $svc.PathName)) {
      $recovery = @()
      try {
        $recovery = @(& sc.exe qfailure ([string]$svc.Name) 2>&1 | ForEach-Object { [string]$_ })
      } catch { AppendError ('service-recovery/' + $svc.Name) $_.Exception.Message }
      $report.services += @{
        name = [string]$svc.Name; display_name = [string]$svc.DisplayName;
        path = [string]$svc.PathName; state = [string]$svc.State;
        start_mode = [string]$svc.StartMode; account = [string]$svc.StartName;
        pid = [int]$svc.ProcessId;
        recovery_query = [string]($recovery -join "`n")
      }
    }
  }
} catch { AppendError 'services' $_.Exception.Message }
try {
  foreach ($driver in @(Get-CimInstance Win32_SystemDriver -ErrorAction Stop)) {
    if (IsRelevant ($driver.Name + ' ' + $driver.DisplayName + ' ' + $driver.PathName)) {
      $filePath = [string]$driver.PathName
      if ($filePath.StartsWith('\??\', [StringComparison]::OrdinalIgnoreCase)) {
        $filePath = $filePath.Substring(4)
      }
      if ($filePath.StartsWith('\SystemRoot\', [StringComparison]::OrdinalIgnoreCase)) {
        $filePath = Join-Path $env:SystemRoot $filePath.Substring(12)
      } elseif ($filePath.StartsWith('System32\', [StringComparison]::OrdinalIgnoreCase)) {
        $filePath = Join-Path $env:SystemRoot $filePath
      }
      $driverSig = $null
      try {
        if (Test-Path -LiteralPath $filePath -PathType Leaf -ErrorAction Stop) {
          $sig = Get-AuthenticodeSignature -LiteralPath $filePath -ErrorAction Stop
          $subject = $null
          if ($null -ne $sig.SignerCertificate) {
            $subject = [string]$sig.SignerCertificate.Subject
          }
          $driverSig = @{status = [string]$sig.Status; signer_subject = $subject}
        }
      } catch { AppendError ('driver-signature/' + $driver.Name) $_.Exception.Message }
      $driverRegistry = $null
      try {
        $serviceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + [string]$driver.Name
        $property = Get-ItemProperty -LiteralPath $serviceKey -ErrorAction Stop
        $driverRegistry = @{
          start = [string]$property.Start;
          type = [string]$property.Type;
          error_control = [string]$property.ErrorControl;
          image_path = [string]$property.ImagePath
        }
      } catch { AppendError ('driver-registry/' + $driver.Name) $_.Exception.Message }
      $report.drivers += @{
        name = [string]$driver.Name; display_name = [string]$driver.DisplayName;
        path = [string]$driver.PathName; resolved_path = $filePath;
        state = [string]$driver.State; start_mode = [string]$driver.StartMode;
        service_type = [string]$driver.ServiceType; signature = $driverSig;
        registry = $driverRegistry
      }
    }
  }
} catch { AppendError 'drivers' $_.Exception.Message }
try {
  foreach ($task in @(Get-ScheduledTask -ErrorAction Stop)) {
    $actions = @()
    foreach ($a in @($task.Actions)) {
      $actions += @{
        execute = [string]$a.Execute;
        arguments = [string]$a.Arguments;
        working_directory = [string]$a.WorkingDirectory
      }
    }
    $combined = [string]$task.TaskName + ' ' + [string]$task.TaskPath
    foreach ($action in $actions) {
      $combined += ' ' + $action.execute + ' ' + $action.arguments + ' ' + $action.working_directory
    }
    if (IsRelevant $combined) {
      $triggers = @()
      foreach ($t in @($task.Triggers)) {
        $triggers += @{
          type = [string]$t.CimClass.CimClassName;
          enabled = [bool]$t.Enabled;
          start_boundary = [string]$t.StartBoundary
        }
      }
      $report.scheduled_tasks += @{
        task_name = [string]$task.TaskName;
        task_path = [string]$task.TaskPath;
        state = [string]$task.State; actions = @($actions);
        triggers = @($triggers)
      }
    }
  }
} catch { AppendError 'scheduled_tasks' $_.Exception.Message }
try {
  foreach ($entry in @(Get-CimInstance Win32_StartupCommand -ErrorAction Stop)) {
    if (IsRelevant ($entry.Name + ' ' + $entry.Command)) {
      $report.startup_entries += @{
        source = 'Win32_StartupCommand'; name = [string]$entry.Name;
        command = [string]$entry.Command; location = [string]$entry.Location
      }
    }
  }
} catch { AppendError 'startup_cim' $_.Exception.Message }
$runKeys = @(
 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
 'HKCU:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
 'HKCU:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
)
foreach ($key in $runKeys) {
  try {
    $item = Get-ItemProperty -LiteralPath $key -ErrorAction Stop
    foreach ($prop in @($item.PSObject.Properties)) {
      if ($prop.Name -like 'PS*') { continue }
      if (IsRelevant ($prop.Name + ' ' + $prop.Value)) {
        $report.startup_entries += @{
          source = 'registry'; location = $key;
          name = [string]$prop.Name; command = [string]$prop.Value
        }
      }
    }
  } catch [System.Management.Automation.ItemNotFoundException] {
    # Absent autostart key is ordinary, not a failure.
  } catch { AppendError ('startup_registry/' + $key) $_.Exception.Message }
}
$since = (Get-Date).AddHours(-72)
$eventSources = @(
 @{name='System'; ids=@(7000,7001,7009,7023,7024,7031,7034,7040,7045)},
 @{name='Application'; ids=@(1000,1001)},
 @{name='Microsoft-Windows-TaskScheduler/Operational'; ids=@(100,101,102,106,129,140,200,201)},
 @{name='Security'; ids=@(4656,4663,4670)},
 @{name='Microsoft-Windows-Windows Defender/Operational'; ids=@(1116,1117,1121,1122,5007)}
)
foreach ($source in $eventSources) {
  try {
    $filter = @{LogName=$source.name; StartTime=$since; Id=$source.ids}
    $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents 250 -ErrorAction Stop)
    foreach ($event in $events) {
      $message = [string]$event.Message
      if (IsRelevant $message) {
        $report.events += @{
          source = [string]$source.name; id = [int]$event.Id;
          time_utc = $event.TimeCreated.ToUniversalTime().ToString('o');
          message = $(if ($message.Length -gt 1600) { $message.Substring(0,1600) } else { $message })
        }
      }
    }
  } catch {
    if ($_.FullyQualifiedErrorId -notlike '*NoMatchingEventsFound*') {
      AppendError ('event_log/' + $source.name) $_.Exception.Message
    }
  }
}
try {
  $status = Get-MpComputerStatus -ErrorAction Stop
  $report.defender = @{
    antivirus_enabled = [bool]$status.AntivirusEnabled;
    realtime_protection = [bool]$status.RealTimeProtectionEnabled;
    tamper_protected = [bool]$status.IsTamperProtected;
    running_mode = [string]$status.AMRunningMode
  }
} catch { AppendError 'defender' $_.Exception.Message }
$json = $report | ConvertTo-Json -Depth 9 -Compress
$bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
[Console]::WriteLine('INC_NOTEBOOK_JSON:' + [Convert]::ToBase64String($bytes))
'''


def _windows_powershell_probe(folder: Path) -> dict:
    """Use supported read-only Windows APIs through PowerShell/CIM."""
    import base64
    import shutil
    import subprocess
    import locale

    interpreter = shutil.which('powershell.exe') or shutil.which('pwsh.exe')
    if not interpreter:
        return {'errors': ['PowerShell executable not found']}

    command = base64.b64encode(_WINDOWS_PROBE.encode('utf-16le')).decode('ascii')
    env = os.environ.copy()
    env['INC_NOTEBOOK_TARGET_DIR'] = str(folder)
    env['INC_NOTEBOOK_TARGETS_JSON'] = json.dumps(TARGETS)
    try:
        proc = subprocess.run(
            [interpreter, '-NoProfile', '-NonInteractive', '-EncodedCommand', command],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=100,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'errors': [f'PowerShell query failed: {exc}']}
    if proc.returncode:
        # Keep stderr bounded; no embedded target data is executed.
        message = proc.stderr.decode(locale.getpreferredencoding(False), 'replace')[:1500]
        return {'errors': [f'PowerShell exit {proc.returncode}: {message}']}
    try:
        output = proc.stdout.decode('ascii', 'replace')
        marker = 'INC_NOTEBOOK_JSON:'
        lines = [line.split(marker, 1)[1].strip() for line in output.splitlines() if marker in line]
        if not lines:
            return {'errors': ['PowerShell produced no machine-readable report']}
        data = json.loads(base64.b64decode(lines[-1], validate=True).decode('utf-8'))
        if not isinstance(data, dict):
            raise ValueError('PowerShell result must be a JSON object')
        return data
    except (ValueError, UnicodeError, binascii.Error) as exc:
        return {'errors': [f'PowerShell report parse failed: {exc}']}


_UNINSTALL_INVENTORY_SCRIPT = r"""
$ErrorActionPreference='Continue'
$entries=@()
$paths=@(
 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
 'HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
foreach($path in $paths) {
  foreach($p in @(Get-ItemProperty -Path $path -ErrorAction SilentlyContinue)) {
    $label=[string]$p.DisplayName+' '+[string]$p.Publisher+' '+[string]$p.InstallLocation
    if($label -match '(?i)JNESS|Momi|Maya|DSesSvc|유해차단') {
      $entries+=@{
        display_name=[string]$p.DisplayName; publisher=[string]$p.Publisher;
        version=[string]$p.DisplayVersion; key=[string]$p.PSPath;
        uninstall_command=[string]$p.UninstallString;
        quiet_uninstall_command=[string]$p.QuietUninstallString;
        install_location=[string]$p.InstallLocation
      }
    }
  }
}
$json=ConvertTo-Json -Compress -Depth 4 -InputObject @($entries)
[Console]::WriteLine('INC_UNINSTALL_JSON:' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json)))
"""


def _windows_uninstall_inventory() -> tuple[list[dict], str | None]:
    """Read registered vendor removal metadata; NEVER execute uninstall commands."""
    if os.name != 'nt':
        return [], 'Windows 전용 제품 제거 등록 정보'
    import base64
    import shutil
    import subprocess
    ps = shutil.which('powershell.exe') or shutil.which('powershell')
    if not ps:
        return [], 'powershell.exe not found'
    encoded = base64.b64encode(_UNINSTALL_INVENTORY_SCRIPT.encode('utf-16le')).decode('ascii')
    try:
        result = subprocess.run(
            [ps, '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=40, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [], f'등록 정보 조회 실패: {exc}'
    if result.returncode:
        return [], f'PowerShell 등록 정보 조회 exit {result.returncode}'
    try:
        output = result.stdout.decode('utf-8-sig', errors='replace')
        lines = [x.split('INC_UNINSTALL_JSON:', 1)[1].strip()
                 for x in output.splitlines() if 'INC_UNINSTALL_JSON:' in x]
        if not lines:
            return [], 'PowerShell 등록 정보 JSON 누락'
        obj = json.loads(base64.b64decode(lines[-1], validate=True).decode('utf-8'))
        if not isinstance(obj, list):
            return [], '제거 등록 정보 형식 오류'
        return [row for row in obj[:100] if isinstance(row, dict)], None
    except (ValueError, UnicodeError, binascii.Error) as exc:
        return [], f'제거 등록 정보 해석 실패: {exc}'


def _rm_locking_processes(path: Path) -> tuple[list[int], str | None]:
    """Query Windows Restart Manager for processes using one named file.

    Restart Manager does not enumerate every kernel driver or prove which
    process caused WinError 5. It is a supplemental read-only signal.
    """
    if os.name != 'nt':
        return [], 'Restart Manager is Windows-only'
    import ctypes.wintypes as w

    class FILETIME(ctypes.Structure):
        _fields_ = [('low', w.DWORD), ('high', w.DWORD)]

    class RM_UNIQUE_PROCESS(ctypes.Structure):
        _fields_ = [('pid', w.DWORD), ('start', FILETIME)]

    class RM_PROCESS_INFO(ctypes.Structure):
        _fields_ = [
            ('process', RM_UNIQUE_PROCESS), ('app_name', ctypes.c_wchar * 256),
            ('service_name', ctypes.c_wchar * 64), ('app_type', w.DWORD),
            ('status', w.ULONG), ('session', w.DWORD), ('restartable', w.BOOL)
        ]

    try:
        dll = ctypes.WinDLL('Rstrtmgr.dll')
        start = dll.RmStartSession
        start.argtypes = [ctypes.POINTER(w.DWORD), w.DWORD, w.LPWSTR]
        start.restype = w.DWORD
        register = dll.RmRegisterResources
        register.argtypes = [w.DWORD, w.UINT, ctypes.POINTER(w.LPCWSTR),
                             w.UINT, ctypes.c_void_p, w.UINT, ctypes.c_void_p]
        register.restype = w.DWORD
        get_list = dll.RmGetList
        get_list.argtypes = [w.DWORD, ctypes.POINTER(w.UINT),
                             ctypes.POINTER(w.UINT), ctypes.POINTER(RM_PROCESS_INFO),
                             ctypes.POINTER(w.DWORD)]
        get_list.restype = w.DWORD
        end = dll.RmEndSession
        end.argtypes = [w.DWORD]
        end.restype = w.DWORD

        session = w.DWORD()
        key = ctypes.create_unicode_buffer(33)
        rc = start(ctypes.byref(session), 0, key)
        if rc != 0:
            return [], f'Restart Manager start failed with code {rc}'
        try:
            item = w.LPCWSTR(str(path))
            rc = register(session.value, 1, ctypes.byref(item), 0, None, 0, None)
            if rc != 0:
                return [], f'Restart Manager register failed with code {rc}'
            needed = w.UINT(0)
            count = w.UINT(0)
            reboot = w.DWORD(0)
            for _ in range(3):
                infos = (RM_PROCESS_INFO * needed.value)() if needed.value else None
                count = w.UINT(needed.value)
                rc = get_list(session.value, ctypes.byref(needed), ctypes.byref(count),
                              infos, ctypes.byref(reboot))
                if rc == 0:
                    return sorted({int(infos[i].process.pid) for i in range(count.value)}) if infos is not None else [], None
                if rc != 234:  # ERROR_MORE_DATA
                    return [], f'Restart Manager query failed with code {rc}'
            return [], 'Restart Manager list changed too frequently'
        finally:
            end(session.value)
    except (OSError, AttributeError, TypeError, ValueError) as exc:
        return [], f'Restart Manager unavailable: {exc}'


def _target_snapshot(folder: Path) -> dict[str, dict]:
    values = {}
    for name in TARGETS:
        p = folder / name
        state = current_state(p)
        entry = {'state': state}
        if state == 'regular':
            try:
                st = p.lstat()
                entry.update(size=st.st_size, file_id=st.st_ino,
                             mtime_ns=st.st_mtime_ns, mode=stat.S_IMODE(st.st_mode))
            except OSError as exc:
                entry['stat_error'] = error_details(exc)
        values[name] = entry
    return values


def _sha256_readonly(path: Path) -> str:
    """Hash with bounded memory; refuse links and non-regular entries."""
    if current_state(path) != 'regular':
        raise OSError('Only regular files can be hashed')
    digest = hashlib.sha256()
    with path.open('rb') as file:
        while True:
            block = file.read(256 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _monitor_changes(folder: Path, seconds: int, interval: float = 1.0) -> list[dict]:
    """Observe file changes without deleting, renaming, or opening processes."""
    if seconds <= 0:
        return []
    baseline = _target_snapshot(folder)
    observations = []
    started = time.monotonic()
    while time.monotonic() - started < seconds:
        time.sleep(min(interval, max(0, seconds - (time.monotonic() - started))))
        now = _target_snapshot(folder)
        for name in TARGETS:
            if now[name] != baseline[name]:
                observations.append({
                    'observed_utc': datetime.now(timezone.utc).isoformat(),
                    'file': name, 'before': baseline[name], 'after': now[name]
                })
        baseline = now
    return observations


def _inspection_report_folder(folder: Path, override: Path | None) -> Path:
    root = override or (Path(os.environ.get('LOCALAPPDATA', tempfile.gettempdir())) /
                        'IncNotebookDeleter' / 'reports')
    root = Path(os.path.abspath(os.path.expanduser(str(root))))
    # Refuse to write reports within the protected target directory.
    try:
        if os.path.commonpath([os.path.normcase(str(root)), os.path.normcase(str(folder))]) == os.path.normcase(str(folder)):
            raise ValueError('진단 보고서는 대상 폴더 밖에 저장해야 합니다')
    except ValueError as exc:
        if '진단 보고서' in str(exc):
            raise
        # Different Windows drives are not nested.
    for candidate in (root, *root.parents):
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise ValueError(f'보고서 폴더 경로 확인 실패: {exc}') from exc
        if stat.S_ISLNK(info.st_mode) or (getattr(info, 'st_file_attributes', 0) & REPARSE_POINT):
            raise ValueError(f'재분석 지점인 보고서 경로는 사용하지 않습니다: {candidate}')
    return root


def _report_text(report: dict) -> str:
    lines = [
        'Inc Notebook Deleter - 읽기 전용 원인 분석',
        '주의: 파일 잠금·서비스 연관성만으로 삭제 거부의 직접 원인을 단정할 수 없습니다.',
        f"분석 시간(UTC): {report['captured_utc']}",
        f"대상 폴더: {report['target_dir']}",
        f"Windows 환경: {report['windows']}",
        f"관리자 권한: {report['admin']}",
        ''
    ]
    for f in report['files']:
        lines.append(f"[{f['name']}] 존재 상태: {f['state']}")
        if 'sha256' in f:
            lines.append(f"  SHA256: {f['sha256']}")
        if f.get('hash_error'):
            lines.append(f"  해시 오류: {f['hash_error']}")
        if 'restart_manager_pids' in f:
            lines.append(f"  Restart Manager PID: {f['restart_manager_pids']}")
        if f.get('restart_manager_error'):
            lines.append(f"  잠금 조회 한계: {f['restart_manager_error']}")
        info = next((x for x in report['windows_data'].get('targets', []) if x.get('name') == f['name']), None)
        if info:
            lines.append(f"  제품: {info.get('company') or '-'} / {info.get('product') or '-'}")
            lines.append(f"  소유자: {info.get('owner') or '-'}")
            sig = info.get('signature') or {}
            lines.append(f"  서명: {sig.get('status') or '-'} / {sig.get('signer_subject') or '-'}")
            acl = info.get('acl') or {}
            lines.append(f"  ACL (상속보호: {acl.get('protected', '?')}):")
            for rule in (acl.get('rules') or [])[:48]:
                lines.append(f"    {rule.get('type')}: {rule.get('principal')} -> {rule.get('rights')} (상속 {rule.get('inherited')})")
        lines.append('')
    categories = (
        ('installed_products', '등록된 제조사 제품 및 공식 제거 명령(조회만)'),
        ('processes', '실행 프로세스'),
        ('services', '연관 서비스 및 복구 동작'),
        ('drivers', '연관 커널 드라이버 후보'),
        ('scheduled_tasks', '연관 예약 작업'),
        ('startup_entries', '연관 자동 실행 항목'),
        ('events', '관련 Windows 이벤트(최근 72시간)')
    )
    for key, label in categories:
        items = report['windows_data'].get(key, []) or []
        lines.append(f'{label}: {len(items)}개 후보')
        for item in items[:60]:
            lines.append(json.dumps(item, ensure_ascii=False, sort_keys=True))
        lines.append('')
    lines.append(f"변화 관찰: {len(report['observations'])}건")
    for item in report['observations'][:100]:
        lines.append(json.dumps(item, ensure_ascii=False, sort_keys=True))
    if report.get('removal_assessment'):
        lines.extend(['', evidence.format_assessment(report['removal_assessment']), ''])
    errors = report['windows_data'].get('errors', []) or []
    if errors:
        lines.append('부분 조회 실패·제한:')
        lines.extend('  - ' + str(err) for err in errors)
    lines.extend([
        '', '가능한 원인: ACL/소유권, 실행 프로세스 잠금, 서비스 보호, 드라이버 필터,',
        '엔드포인트 보안 정책. 이 보고서는 관련 항목을 식별할 뿐 보호 기능 개입을 증명하지 않습니다.',
        '드라이버·서비스·예약 작업은 변경하지 않았습니다.'
    ])
    return '\n'.join(lines) + '\n'


def analyze_protection(folder: Path, *, report_dir: Path | None = None,
                       watch_seconds: int = 0, reference_report: dict | None = None) -> tuple[dict, Path, Path]:
    """Read-only incident report, never calls the deletion implementation."""
    if not 0 <= watch_seconds <= 300:
        raise ValueError('--watch-seconds 허용 범위는 0~300초입니다')
    folder = normalize_directory(folder)
    output_dir = _inspection_report_folder(folder, report_dir)
    data = {
        'schema_version': 1,
        'captured_utc': datetime.now(timezone.utc).isoformat(),
        'target_dir': str(folder),
        'windows': os.name == 'nt',
        'admin': is_admin(),
        'files': [], 'windows_data': {}, 'observations': [],
        'notes': [
            '진단은 읽기 전용이며 실제 파일 삭제·프로세스 종료·ACL 수정 없음',
            '서비스/드라이버/예약 작업은 파일명·제조사 단서에 따른 후보만 표시',
            '액세스 거부가 정확히 어느 보안 구성요소 때문인지 별도 추적 없이는 단정 불가'
        ]
    }
    snapshot = _target_snapshot(folder)
    for name in TARGETS:
        f = {'name': name, **snapshot[name]}
        if snapshot[name]['state'] == 'regular':
            path = folder / name
            try:
                f['sha256'] = _sha256_readonly(path)
            except OSError as exc:
                f['hash_error'] = error_details(exc)
            if os.name == 'nt':
                pids, error = _rm_locking_processes(path)
                f['restart_manager_pids'] = pids
                if error:
                    f['restart_manager_error'] = error
        data['files'].append(f)
    if os.name == 'nt':
        data['windows_data'] = _windows_powershell_probe(folder)
        installed, inventory_error = _windows_uninstall_inventory()
        data['windows_data']['installed_products'] = installed
        if inventory_error:
            data['windows_data'].setdefault('errors', []).append(
                'uninstall_registry: ' + inventory_error
            )
    else:
        data['windows_data'] = {'errors': ['Windows 전용 API는 이 환경에서 실행하지 않음']}
    if watch_seconds:
        data['observations'] = _monitor_changes(folder, watch_seconds)

    data['removal_assessment'] = evidence.assess_report(data, reference_report)

    output_dir.mkdir(parents=True, exist_ok=True)
    import uuid
    stem = (datetime.now(timezone.utc).strftime('diagnostics-%Y%m%d-%H%M%S-') +
            uuid.uuid4().hex[:8])
    json_file = output_dir / (stem + '.json')
    text_file = output_dir / (stem + '.txt')
    with json_file.open('x', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write('\n')
    with text_file.open('x', encoding='utf-8') as f:
        f.write(_report_text(data))
    return data, json_file, text_file


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="지정한 4개 파일의 실제 삭제 및 삭제 검증")
    parser.add_argument("--target-dir", type=Path, default=DEFAULT_DIR)
    parser.add_argument("--execute", action="store_true", help="실제 파일 삭제")
    parser.add_argument("--analyze-protection", action="store_true",
                        help="서비스·드라이버·접근 제어·자동 실행·이벤트 조사(읽기 전용)")
    parser.add_argument("--report-dir", type=Path, default=None,
                        help="분석 보고서 저장 폴더 (기본: 사용자 데이터 폴더)")
    parser.add_argument("--watch-seconds", type=int, default=0,
                        help="대상 파일 변경 감시 시간, 0~300초 (변경 없음이 정상일 수 있음)")
    parser.add_argument("--confirm", default="", help="미리보기 화면에서 안내된 확인값")
    parser.add_argument("--reference-report", type=Path, default=None,
                        help="이전 진단 JSON/ZIP(예: OpenDrop.zip)과 SHA-256·차단 근거 대조")
    parser.add_argument("--log-file", type=Path, default=None)
    args = parser.parse_args(argv)
    try:
        folder = normalize_directory(args.target_dir)
    except ValueError as exc:
        print(f"[경로 오류] {exc}", file=sys.stderr)
        return 2
    reference = None
    if args.reference_report is not None:
        try:
            reference = evidence.load_reference_report(args.reference_report, folder)
        except (OSError, ValueError) as exc:
            print(f'[참조 보고서 오류] {exc}', file=sys.stderr)
            return 2
    if args.analyze_protection:
        if args.execute or args.confirm:
            print("[옵션 오류] 분석 모드와 삭제/확인 옵션을 함께 사용할 수 없습니다", file=sys.stderr)
            return 2
        try:
            report, json_path, txt_path = analyze_protection(
                folder, report_dir=args.report_dir, watch_seconds=args.watch_seconds,
                reference_report=reference
            )
        except (ValueError, OSError) as exc:
            print(f"[분석 오류] {exc}", file=sys.stderr)
            return 3
        print("[분석 완료] 삭제/서비스 중단/권한 변경 없이 조회했습니다.")
        print(f"JSON 보고서: {json_path}")
        print(f"텍스트 보고서: {txt_path}")
        assessment = report.get('removal_assessment')
        if assessment:
            print(evidence.format_assessment(assessment))
        labels = (("installed_products", "제조사 제품 등록"), ("services", "서비스"), ("drivers", "드라이버"),
                  ("scheduled_tasks", "예약 작업"),
                  ("startup_entries", "자동 실행"), ("events", "이벤트"))
        windows_data = report["windows_data"]
        for key, label in labels:
            print(f"{label} 연관 후보: {len(windows_data.get(key, []) or [])}개")
        errors = windows_data.get("errors", []) or []
        if errors:
            print(f"[부분 조회 제한] {len(errors)}건. 보고서의 오류 항목을 확인하세요.")
        return 0 if not (os.name == 'nt' and len(windows_data) == 1 and 'errors' in windows_data) else 4
    if args.watch_seconds or args.report_dir is not None:
        print("[옵션 오류] --report-dir 및 --watch-seconds는 --analyze-protection과 사용하세요", file=sys.stderr)
        return 2
    token = confirmation_token(folder)
    if args.execute and args.confirm != token:
        print(f"[확인값 오류] 먼저 미리보기로 확인값을 확인하세요: {token}", file=sys.stderr)
        return 2
    if args.execute and is_windows_system_dir(folder) and not is_admin():
        print("[권한 부족] Windows 시스템 폴더 삭제에는 관리자 권한이 필요합니다", file=sys.stderr)
        return 2
    log_path = args.log_file or (Path(os.environ.get("LOCALAPPDATA", tempfile.gettempdir())) / "IncNotebookDeleter" / "deletion-log.jsonl")
    log_path = Path(os.path.abspath(os.path.expanduser(str(log_path))))
    try:
        log_path.relative_to(folder)
    except ValueError:
        pass
    else:
        print("[로그 오류] 로그는 삭제 대상 디렉터리 외부에 저장해야 합니다", file=sys.stderr)
        return 2
    mode = "execute" if args.execute else "preview"
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        if log_path.is_symlink():
            raise OSError("로그 파일로 심볼릭 링크를 사용할 수 없습니다")
        with log_path.open("a", encoding="utf-8") as log_file:
            print(f"대상 폴더: {folder}")
            print(f"모드: {'실제 삭제' if args.execute else '미리보기(삭제 없음)'}")
            print(f"로그: {log_path}")
            if reference is not None:
                print(f'[참조 보고서] {reference.get("captured_utc", "시간 정보 없음")} 기준의 과거 증거를 사용합니다.')
                print('현재 파일 해시가 참조 시점과 다르면 삭제하지 않습니다.')
            statuses = []
            expected_hashes = evidence.baseline_hashes(reference) if reference else {}
            for name in TARGETS:
                path = folder / name
                state = current_state(path)
                if not args.execute:
                    status = "missing" if state == "missing" else ("preview" if state == "regular" else "failed")
                    detail = state
                elif state == "missing":
                    status, detail = "missing", "처음부터 없음"
                elif reference is not None and state == 'regular':
                    expected = expected_hashes.get(name)
                    if not expected:
                        status, detail = 'failed', '참조 보고서에 SHA-256이 없어 동일성을 검증할 수 없음'
                    else:
                        try:
                            actual = _sha256_readonly(path).casefold()
                        except OSError as exc:
                            status, detail = 'failed', '삭제 전 해시 계산 실패: ' + error_details(exc)
                        else:
                            if actual != expected:
                                status, detail = 'failed', (
                                    '참조 보고서와 파일 SHA-256 불일치, 다른 파일일 수 있어 삭제하지 않음'
                                )
                            else:
                                status, detail = remove_and_verify(path, folder)
                else:
                    status, detail = remove_and_verify(path, folder)
                if status == 'failed' and reference is not None:
                    hint = evidence.describe_known_access_denial(name, reference)
                    if hint:
                        detail += ' | ' + hint
                statuses.append(status)
                log_record(log_file, mode=mode, path=path, status=status, detail=detail)
                print(f"[{status.upper()}] {name}: {detail}")
            if reference is not None and not args.execute:
                historical = evidence.assess_report(reference)
                print('[이전 진단 보고서 기반 보호 분석 - 현재 상태 아님]')
                print(evidence.format_assessment(historical))
                for name in TARGETS:
                    if current_state(folder/name) != 'regular':
                        continue
                    try:
                        old = expected_hashes.get(name)
                        new = _sha256_readonly(folder/name)
                        print(f'[해시 대조] {name}: ' + (
                            '일치' if old and old.casefold() == new.casefold() else '불일치/비교 불가'
                        ))
                    except OSError as exc:
                        print(f'[해시 대조 실패] {name}: {error_details(exc)}')
            if args.execute:
                failures = statuses.count("failed")
                deletions = statuses.count("deleted")
                result = "SUCCESS" if failures == 0 and deletions > 0 else ("PARTIAL" if deletions else ("FAILED" if failures else "NOT_FOUND"))
            else:
                result = "PREVIEW"
            print(f"최종 결과: {result}")
            if not args.execute:
                print(f"실제 삭제 명령: py -3 verified_delete.py --target-dir \"{folder}\" --execute --confirm {token}")
            log_record(log_file, mode=mode, path=folder, status=result, detail="summary")
            return 1 if args.execute and result in {"FAILED", "PARTIAL"} else 0
    except OSError as exc:
        print(f"[로그/파일 시스템 오류] {error_details(exc)}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    # Ensure Korean diagnostics remain printable on legacy Windows code pages.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")
        except (AttributeError, OSError, ValueError):
            pass
    raise SystemExit(main())
