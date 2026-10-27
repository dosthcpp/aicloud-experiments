# AI Cloud experiments

로컬 AI 워크로드를 실행하기 전에 작업 계약과 실행 문맥을 검증하고, 결과에 대한 메타데이터 추적을 만드는 실험 소스입니다. 기존 AI Cloud 작업 폴더에서 독립적으로 검토 가능한 계약·추적 부분만 공개한 스냅샷입니다.

## 구성

- `contracts/workload-contract.schema.json`: embedding, recap, classification 워크로드의 JSON 계약 스키마.
- `scripts/validate_contract.py`: 신뢰된 실행 문맥, 경로, 허용된 모델 경로, 네트워크·비용·fallback 조건을 검증하는 함수와 CLI.
- `scripts/artifact_policy.py`: 아티팩트를 허용된 저장 경로 아래로 제한하는 정책.
- `scripts/emit_trace.py`: 검증한 계약과 결과 아티팩트에서 내용 수집 없는 메타데이터 trace를 생성하는 함수와 CLI.

Python 3.10 이상의 표준 라이브러리를 사용하는 코드입니다. CLI 옵션은 `python3 scripts/validate_contract.py --help`, `python3 scripts/emit_trace.py --help`로 확인할 수 있습니다.

## 원래 환경과의 관계

Tony AI Lab의 Paperclip 실행 문맥, 고정 company ID, 모델 경로 및 저장 경로 정책을 전제로 합니다. 별도 환경에서 사용하려면 해당 정책을 명시적으로 재설정해야 합니다. Tony AI Lab 식별자는 이 실험의 소유자 측 연구 환경을 가리킵니다.

실제 실행을 위한 runtime gate, 운영 서비스 manifest, 배포 스크립트, 인증 파일, 운영 기록, DB 및 백업은 포함하지 않습니다. 전체 AI Cloud 서비스나 Linux 샌드박스를 이 레포만으로 기동할 수 있다는 의미는 아닙니다.

## 공개 점검

파일별 비밀·개인정보·고용주 자료 후보를 점검하고, 선택한 소스는 저장 전에 Gitleaks로 다시 검사했습니다. Python 구문과 JSON 파싱, 외부 서비스 없이 실행 가능한 도움말·정책 동작을 확인합니다. 운영 서버 접속, 배포, 외부 모델 API 호출은 공개 검증 범위에 포함하지 않습니다.
