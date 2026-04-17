# Inc Notebook Deleter

`delete_agent` 저장소에서 표적으로 삼은 파일들을 한 번에 삭제하기 위한 Python 스크립트입니다.

이 프로젝트는 다음 두 저장소의 아이디어를 결합합니다.

- **타겟 목록**: `ji5zi5/delete_agent`의 `삭제.bat`
- **삭제 전략**: `jsk1004ha/Force_deleter`의 강제 삭제 방식(일반 삭제 → 잠금 프로세스 종료 → 재시도)

## 파일

- `bulk_delete_agent_targets.py`: 메인 실행 스크립트

## 요구 사항

- Python 3.10+
- Windows 10/11 권장
  - Windows에서는 Restart Manager API + `taskkill`을 사용하여 잠금 프로세스 종료 후 재시도합니다.
  - 비-Windows 환경에서는 일반 삭제만 시도합니다.

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
