# Inc Notebook Deleter — 증거 기반 보호 진단 및 검증형 파일 삭제

지원 환경: Windows 10/11, Python 3.10 이상 (별도 `pip install` 불필요).

이 버전은 **2026-10-19 진단 결과에서 확인된 보호 패턴**을 코드 및 테스트에 반영했습니다. 이전 프로그램과 달리 `Everyone: Deny Delete` ACL, 실행 중인 서비스 및 파일 SHA-256 변경 여부를 파일별로 구분합니다. 삭제 옵션은 실제 Windows 파일 삭제 기능을 호출하고 파일이 사라졌는지 재확인합니다. 운영체제 보안 정책과 서비스 자체 보호를 우회하지 않습니다.

## 1. 보고서에서 확인된 상태 (수집 당시)

| 파일 | ACL: Everyone 명시적 Delete 거부 | 관련 실행 상태 |
|---|---|---|
| `lqndauccd.exe` | 확인 | `SvcMayaEC` 서비스 실행 |
| `ooajphjh.exe` | 확인 | 잠금 프로세스 미보고 |
| `qukapttp.exe` | 확인 | 프로세스 실행 |
| `rwtyijsa.exe` | 확인 | `svcMayaDSes` 서비스 실행 |

- 네 파일의 소유자는 `NT AUTHORITY\SYSTEM`이고, 보고서 수집 시에는 **관리자 권한이 아니었습니다**.
- **명시적 Deny가 Administrator의 Allow보다 우선 적용될 수 있으므로**, 관리자 권한만으로 `WinError 5`가 해결된다고 보장할 수 없습니다.
- `Restart Manager`에 잠금이 보고되지 않은 파일도 ACL 때문에 삭제가 거부될 수 있습니다.
- 서명 상태 `Valid`는 해당 파일이 악성코드인지에 대한 최종 판정이 아닙니다.
- 관련 드라이버 후보 0개라는 결과 역시 보호 드라이버가 존재하지 않는다는 증명은 아닙니다.
- **코드는 ACL 변경, 소유권 탈취, 서비스·보호 프로세스 종료, 보안 제품 비활성화를 수행하지 않습니다.**

## 2. 시작하기

GitHub 저장소를 다운로드하면 `analyze_protection.cmd`로 바로 읽기 전용 조사를 시작할 수 있습니다. `run_verified_delete.cmd`는 기본적으로 삭제 **미리보기**만 수행합니다. 기존 분석 보고서를 로컬에 `reference_opendrop_20261019.json`이라는 이름으로 별도로 배치하면 두 CMD 실행기가 자동으로 참조하지만, 파일이 없어도 작동합니다. Windows의 `python` 명령이 비정상이라면 `py -3`을 사용합니다.

**개인 PC의 파일 해시·PID·서비스 목록 등이 포함된 진단 보고서는 공개 저장소에 포함하지 않습니다.** 과거 ZIP에 들어 있던 보고서를 참조하려면 직접 자신의 컴퓨터에서 `--reference-report "C:\path\to\OpenDrop.zip"`으로 경로를 지정하거나 기존 다운로드 ZIP의 `reference_opendrop_20261019.json`을 사용하세요. 참조 보고서는 선택 사항이며, 제공하지 않아도 미리보기 및 삭제 기능이 작동합니다.

기존 15개 파일 대상으로 동작하던 구현 `bulk_delete_agent_targets.py`는 하위 호환을 위해 보존했습니다. **권장 새 프로그램은 `verified_delete.py`이며, 새 Windows 빌드 역시 이를 사용합니다.**

권장 분석 명령 (파일 삭제 없음):

```cmd
py -3 verified_delete.py --analyze-protection --target-dir "C:\Windows\SysWOW64"
```

이 명령은 파일 해시, 디지털 서명, 소유자, ACL, 서비스·프로세스·드라이버 후보, 제거 프로그램 등록 정보(명령 조회만), 자동 실행, 이벤트 로그를 **현재 PC에서 다시 조회**한 뒤 이전 보고서와 비교합니다. 수집 실패한 항목은 표시합니다.

현재 파일을 과거 보고서와 비교하는 미리보기 (파일 삭제 없음):

```cmd
py -3 verified_delete.py --target-dir "C:\Windows\SysWOW64"
```

`reference_opendrop_20261019.json` 대신 사용자 원본 ZIP도 사용할 수 있습니다. ZIP은 압축을 해제하거나 내부 파일을 실행하지 않고 읽습니다.

```cmd
py -3 verified_delete.py --analyze-protection --reference-report "OpenDrop.zip" --target-dir "C:\Windows\SysWOW64"
```

> 보고서에 적힌 SHA-256은 **2026-10-19 당시의 스냅샷**입니다. 파일이 패치되거나 재설치되면 값이 달라질 수 있습니다. 해시 불일치만으로 악성코드라고 판정하지 않습니다.

## 3. 실제 삭제 기능

1. 미리보기를 실행해 `DELETE-XXXXXXXXXXXX` 확인값을 읽습니다.
2. Windows 시스템 디렉터리 대상이라면 관리자 권한으로 CMD를 엽니다.
3. 명시적 실행 옵션을 사용합니다.

```cmd
py -3 verified_delete.py --target-dir "C:\Windows\SysWOW64" --execute --confirm DELETE-XXXXXXXXXXXX
```

`DELETE-XXXXXXXXXXXX`는 프로그램에 표시되는 **실제 확인값**으로 교체해야 합니다.

- 허용된 네 파일 이름 밖의 대상은 삭제할 수 없습니다.
- `--reference-report`를 별도로 지정하면 현재 SHA-256이 보고서와 **일치한 파일만 삭제 시도**합니다. 불일치하거나 해시를 읽지 못하면 실패로 기록하고 삭제하지 않습니다.
- 실제 삭제 호출은 `Path.unlink()`이며 호출 이후에도 파일이 남았으면 절대로 성공이라고 보고하지 않습니다.
- 현재 진단에서 확인된 ACL `Everyone: Deny Delete`가 유지되는 동안에는 실제 삭제가 `WinError 5`로 실패할 가능성이 높습니다. 이 프로그램이 해당 권한/보호 체계를 우회한다고 주장하지 않습니다.
- 삭제 가능한 별도의 승인된 디렉터리에서 정상 파일에 대한 실제 삭제 및 성공/실패 처리 동작은 로컬 테스트로 검증했습니다.

삭제 로그는 `%LOCALAPPDATA%\IncNotebookDeleter\deletion-log.jsonl`, 읽기 전용 분석 보고서는 `%LOCALAPPDATA%\IncNotebookDeleter\reports`에 저장됩니다.

## 4. 제품 제거 등록 정보 확인

분석 모드는 설치된 제품 등록 정보(HKLM/HKCU Uninstall 키)를 읽어서 제조사·제품명·제거 명령을 보고서에 표시합니다. **명령은 조회만 하며 자동 실행하지 않습니다.** 관리형 제품인 경우 제거 등록 정보가 없을 수 있고, 등록 정보가 있다고 해서 인증된 제거가 보장되는 것도 아닙니다. 제거 명령에 개인 계정 정보가 포함됐을 가능성을 고려해 공유 전 보고서를 확인하세요.

## 5. 실패 후 권장 절차

`WinError 5`와 명시적 ACL 삭제 거부가 함께 있으면 `taskkill`을 반복하거나 삭제 명령의 횟수를 늘리는 것은 근본 해결책이 아닙니다. 정상 프로그램이 변조됐거나 악성 동작이 의심된다면 신뢰할 수 있는 백신의 오프라인 검사, 제조사 복구/제거 도구, 필요할 경우 안전한 설치 미디어를 이용한 Windows 복구를 고려하세요. 시스템 또는 조직 정책을 변경하는 작업은 관리 주체와 조율해야 합니다.

## 6. 테스트

```cmd
py -3 -m unittest -v test_verified_delete test_verified_diagnostics test_removal_assessment
```

주요 검증: 임시 파일 실제 삭제, 삭제 후 존재 검사, 범위 제한, 심볼릭 링크 보호, 재시도 오류, 기존 진단의 읽기 전용 동작, 보고서 ZIP/JSON 파서의 크기·경로·이름 검증, SHA-256 불일치 차단, ACL/서비스 상태 분류.

**검증 범위:** 로컬 임시 파일 단위 테스트. 사용자 Windows PC의 보호된 네 파일이 실제로 삭제되거나 Windows PowerShell 조사 명령이 그 PC에서 모두 성공했다고 검증한 것은 아닙니다.

## 7. GitHub Windows EXE 빌드

`main`에 변경을 푸시하면 GitHub Actions에서 기존·새 테스트를 실행하고 **새 `verified_delete.py`를 실행 파일 `inc-notebook-deleter.exe`로 빌드**합니다. 이 EXE는 별도의 Python 설치가 필요하지 않으며, 기본 실행은 삭제하지 않는 미리보기입니다. ZIP 아티팩트에는 기기에서 수집한 보고서가 포함되지 않습니다.

관련 실행기: `run_verified_delete.cmd`(미리보기/삭제 옵션 전달), `analyze_protection.cmd`(읽기 전용 조사), `analyze_reference.cmd`(가능할 때 로컬 과거 보고서와 비교).

기존 구현 및 사용법은 `docs/legacy.md`를 참조하세요.
