# Changelog

## 2026-10-19 (Windows 인코딩 오류 수정)

- Windows CP1252 등 레거시 코드 페이지에서 한국어 출력 시 발생하던 `UnicodeEncodeError` 수정.
- Python과 패키징 EXE의 진단 모드에서 레거시 인코딩 회귀 테스트 수행.

## 2026-10-19 (시작 및 모드 동작 수정)

- EXE의 자동 UAC 요청을 제거하여 일반 권한에서 진단 가능하도록 수정.
- 인자 없이 실행 시 검사/삭제 메뉴 표시 및 창 유지.
- `--diagnose`와 `--mode check/delete` 모드 구분.
- Python/EXE 실행 진단 배치 및 예외 로그 도입.
- Windows CI에서 .py 및 실제 EXE를 각각 실행하는 스모크 테스트 추가.

## 2026-10-19

- EXE 빌드에 UAC 관리자 권한 요청 매니페스트 추가.
- 관리자 권한 검사, 파일별 Windows 오류 코드와 실패 원인 표시.
- 링크/폴더/비정규 대상 보호, 대상 EXE와 일치하는 잠금 프로세스만 종료.
- `--dry-run` 상태 구분과 선택적 `--schedule-reboot` 추가.
- Windows CI에 단위 테스트 추가.

## 2026-04-17

- `bulk_delete_agent_targets.py` 추가.
  - `delete_agent`의 표적 파일 목록을 상수로 내장.
  - `Force_deleter` 스타일의 강제 삭제 로직(일반 삭제 → Restart Manager 조회 → `taskkill` → 재시도) 구현.
  - `--target-dir`, `--retries`, `--dry-run` CLI 옵션 추가.
- EXE 빌드 자동화를 위한 파일 추가.
  - `requirements-build.txt`에 PyInstaller 빌드 의존성 명시.
  - `.github/workflows/build-exe.yml`에 Windows EXE 빌드/아티팩트 업로드 워크플로 추가.
- 사용법 및 EXE 빌드 절차 문서화(`README.md`).
