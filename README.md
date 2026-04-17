# Inc Notebook Deleter

`delete_agent` 저장소에서 표적으로 삼은 파일들을 한 번에 삭제하기 위한 Python 스크립트입니다.

이 프로젝트는 다음 두 저장소의 아이디어를 결합합니다.

- **타겟 목록**: `ji5zi5/delete_agent`의 `삭제.bat`
- **삭제 전략**: `jsk1004ha/Force_deleter`의 강제 삭제 방식(일반 삭제 → 잠금 프로세스 종료 → 재시도)

## 파일

- `bulk_delete_agent_targets.py`: 메인 실행 스크립트
- `requirements-build.txt`: EXE 빌드(PyInstaller) 의존성 목록
- `.github/workflows/build-exe.yml`: GitHub Actions 기반 Windows EXE 자동 빌드

## 요구 사항

### 실행

- Python 3.10+
- Windows 10/11 권장
  - Windows에서는 Restart Manager API + `taskkill`을 사용하여 잠금 프로세스 종료 후 재시도합니다.
  - 비-Windows 환경에서는 일반 삭제만 시도합니다.

### EXE 빌드

- PyInstaller (`requirements-build.txt` 참고)
- Windows 환경에서 빌드 권장
  - `.exe`는 Windows에서 빌드하는 것이 가장 안정적입니다.

## 사용법

### 기본 실행 (SysWOW64 대상)

```bash
python bulk_delete_agent_targets.py
```

### 대상 디렉터리 지정

```bash
python bulk_delete_agent_targets.py --target-dir "C:\Windows\SysWOW64"
```

### 재시도 횟수 지정

```bash
python bulk_delete_agent_targets.py --retries 5
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
pyinstaller --clean --onefile --name inc-notebook-deleter bulk_delete_agent_targets.py
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
- `1`: 하나 이상 삭제 실패

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
