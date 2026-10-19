# Inc Notebook Deleter

`delete_agent` 저장소에서 표적으로 삼은 파일들을 한 번에 삭제하기 위한 Python 스크립트입니다.

이 프로젝트는 다음 두 저장소의 아이디어를 결합합니다.

- **타겟 목록**: `ji5zi5/delete_agent`의 `삭제.bat`
- **삭제 전략**: `jsk1004ha/Force_deleter`의 강제 삭제 방식(일반 삭제 → 잠금 프로세스 종료 → 재시도)

## 파일

- `bulk_delete_agent_targets.py`: 메인 실행 스크립트
- `run-notebook-deleter.cmd`: 실제 Python 설치를 확인하고 실행하는 Windows 실행기
- `run-diagnostics.cmd`: Python 및 EXE 시작 문제 진단
- `requirements-build.txt`: EXE 빌드(PyInstaller) 의존성 목록
- `.github/workflows/build-exe.yml`: GitHub Actions 기반 Windows EXE 자동 빌드

## 요구 사항

### 실행

- Python 3.10+
- Windows 10/11 권장
  - Windows에서는 관리자 권한 확인, Restart Manager를 통한 잠금 확인 및 제한된 `taskkill` 재시도를 지원합니다.
  - 잠금 프로세스는 **삭제 대상 EXE 자체가 실행 중인 경우에만** 종료를 시도합니다. 파일을 열어본 Explorer 등 다른 프로세스는 종료하지 않습니다.
  - 시스템 디렉터리를 대상으로 할 경우 관리자 권한이 필요합니다. 조직 관리 장치는 관리자 승인 및 정책을 확인하세요.
  - 비-Windows 환경에서는 일반 파일 삭제만 시도합니다.

### EXE 빌드

- PyInstaller (`requirements-build.txt` 참고)
- Windows 환경에서 빌드 권장
  - `.exe`는 Windows에서 빌드하는 것이 가장 안정적입니다.

## `python`을 실행하면 `Python`만 출력될 때

`python bulk_delete_agent_targets.py --dry-run` 명령이 `Python`만 출력하면 스크립트가 실행되지 않았을 가능성이 큽니다. 현재 명령이 **실제 Python 인터프리터가 아닌 Windows 앱 실행 별칭 또는 다른 프로그램**을 가리킬 수 있습니다. 코드 수정을 반복해도 실행기 연결은 자동으로 고쳐지지 않습니다.

**`run-notebook-deleter.cmd`를 실행**하면 실제 Python 3.10 이상이 작동하는지 확인한 다음 스크립트를 실행합니다. 실행 인자를 전달할 수도 있습니다.

```cmd
run-notebook-deleter.cmd --dry-run --target-dir "C:\temp"
run-notebook-deleter.cmd --diagnose
```

직접 확인하려면 다음 명령의 결과를 비교하세요.

```cmd
where python
python -c "print(123)"
py -3 --version
py -3 -u bulk_delete_agent_targets.py --dry-run --target-dir "C:\temp"
```

- `python -c "print(123)"`은 반드시 `123`을 출력해야 정상입니다. `Python`만 출력한다면 Python 인터프리터까지 도달하지 못한 것입니다.
- `py -3`가 작동한다면 `python` 대신 사용하세요.
- 두 명령이 모두 정상 실행되지 않으면 Python 3.10 이상을 설치하고, Windows **설정 → 앱 → 고급 앱 설정 → 앱 실행 별칭**에서 Python 별칭을 점검하세요.
- EXE는 Python 설치와 별개이므로 시작에 실패한다면 `run-diagnostics.cmd`에서 EXE 항목의 종료 코드와 오류를 확인하세요.

## 실행이 되지 않는 경우 (Windows)

**`run-diagnostics.cmd`를 더블 클릭해 실행**하면 .py 실행에 필요한 Python을 검증하고 EXE 시작을 별도로 검사합니다. 모든 단계는 삭제를 수행하지 않습니다. 결과는 `%TEMP%\inc-notebook-deleter-diagnostic.log`에 저장되며 마지막에 창이 열린 채로 남습니다.

명령행 확인 방법:

```cmd
py -3 -u bulk_delete_agent_targets.py --diagnose
```

```cmd
.\dist\inc-notebook-deleter.exe --diagnose
```

- `--diagnose`: 시작 환경과 파일 존재 상태 검사, 삭제 없음.
- `--mode check`, `--dry-run`: 삭제 없이 파일 상태만 확인.
- `--mode delete`: 실제 삭제. 보호된 시스템 폴더는 관리자 승인 필요.
- EXE는 관리자 권한을 무조건 요구하지 않도록 빌드됩니다. 검사 후 실제 삭제가 필요하면 관리자 권한 CMD에서 실행하세요.
- Windows에서 한글을 출력할 때 CP1252 등 일부 코드 페이지에서는 `UnicodeEncodeError`가 발생했습니다. 실행 시 표준 출력과 오류 출력을 UTF-8로 설정하도록 수정했습니다.
- 예기치 않은 Python 예외는 `%TEMP%\inc-notebook-deleter-error.log`에 기록됩니다.

## 사용법

### 기본 실행 (SysWOW64 대상)

인자 없이 실행하면 검사/삭제 선택 메뉴가 표시됩니다. 검사 모드는 관리자 권한 없이 사용할 수 있고 파일을 삭제하지 않습니다. 실제 삭제는 관리자 승인 및 추가 확인이 필요합니다.

```cmd
run-notebook-deleter.cmd
```

### 대상 디렉터리 지정

```bash
python bulk_delete_agent_targets.py --target-dir "C:\Windows\SysWOW64"
```

### 재시도 횟수 지정

```bash
python bulk_delete_agent_targets.py --retries 5
```

### 재부팅 후 삭제 예약 (선택 사항)

파일 잠금으로 즉시 삭제할 수 없다면 다음 옵션을 명시적으로 추가할 수 있습니다. 예약된 파일은 아직 삭제된 것이 아니며 Windows를 재부팅한 뒤 다시 확인해야 합니다.

```powershell
python bulk_delete_agent_targets.py --schedule-reboot
```

### 실제 삭제 없이 확인

```bash
python bulk_delete_agent_targets.py --dry-run --target-dir "C:\temp"
```

## EXE 만들기

### 로컬(Windows)에서 직접 빌드

```bash
python -m pip install --upgrade pip
pip install -r requirements-build.txt
pyinstaller --clean --onefile --console --name inc-notebook-deleter bulk_delete_agent_targets.py
```

생성 파일:

- `dist/inc-notebook-deleter.exe`

### GitHub Actions로 빌드 후 내려받기

1. 저장소를 GitHub에 푸시합니다.
2. GitHub 저장소의 **Actions** 탭으로 이동합니다.
3. **Build Windows EXE** 워크플로를 수동 실행(`workflow_dispatch`)하거나 `main` 브랜치 푸시로 자동 실행합니다.
4. 실행이 끝나면 아티팩트 `inc-notebook-deleter-windows-exe`를 다운로드합니다.

## 종료 코드

- `0`: 전체 성공(또는 원래 없음)
- `1`: 하나 이상 삭제 실패 (파일별 WinError 및 실패 원인을 확인)
- `2`: 관리자 권한 필요
- `3`: 즉시 삭제 실패 파일이 재부팅 시 삭제되도록 예약됨
- `10`: 프로그램 내부 예외 (오류 로그 참조)

## 대상 파일 목록

다음 파일들을 지정 디렉터리에서 일괄 삭제 시도합니다.

- `llrxdgfkm.exe`
- `lqndauccd.exe`
- `neagnhoaq.exe`
- `nfowjxyfd.exe`
- `ooajphjh.exe`
- `osurugwgp.exe`
- `qlnsmvsi.exe`
- `qukapttp.exe`
- `rwtyijsa.exe`
- `ryomuigoq.exe`
- `rzzykzbis.exe`
- `tpnvpltow.exe`
- `vfoxujww.exe`
- `ylirkidg.exe`
- `mprogramicon.ico`

## 문제 해결

- `WinError 5` (액세스 거부): 관리자 권한을 확인하고, 조직 관리 장치라면 승인된 제거 절차를 이용하세요. 프로그램은 파일 소유권/ACL을 강제로 변경하지 않습니다.
- `WinError 32` (다른 프로세스가 사용 중): 사용 중인 EXE가 자기 자신일 때만 종료를 시도합니다. 실패하면 관리자에게 문의하거나 `--schedule-reboot`를 선택할 수 있습니다.
- `[없음]`: 해당 이름의 파일이 실제로 없는 상태입니다. 성공적으로 삭제했다는 의미는 아닙니다.
- `[예정]`: `--dry-run`으로 대상만 확인했으며 삭제하지 않았습니다.
- `[예약됨]`: 아직 삭제되지 않았습니다. 재부팅 후 다시 검사하세요.
- 링크/디렉터리처럼 일반 파일이 아닌 경로는 삭제하지 않습니다.

**주의:** 파일 이름만으로 악성 파일 여부를 판별할 수 없습니다. 학교·조직에서 관리하는 필터링/보안 프로그램은 관리자 승인 없이 제거하지 마세요. 이 도구는 Windows의 접근 제어, 정책 또는 별도 변조 방지 기능을 우회하지 않습니다.
