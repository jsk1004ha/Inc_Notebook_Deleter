# Changelog

## 2026-04-17

- `bulk_delete_agent_targets.py` 추가.
  - `delete_agent`의 표적 파일 목록을 상수로 내장.
  - `Force_deleter` 스타일의 강제 삭제 로직(일반 삭제 → Restart Manager 조회 → `taskkill` → 재시도) 구현.
  - `--target-dir`, `--retries`, `--dry-run` CLI 옵션 추가.
- 사용법 및 동작 방식 문서화(`README.md`).
