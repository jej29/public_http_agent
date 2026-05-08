# public_http_agent

`public_http_agent`는 웹 애플리케이션의 정보 노출과 보안 설정 오류를 찾기 위한 HTTP 중심 DAST 에이전트입니다.

이 스캐너는 다음 원칙을 중심으로 설계되어 있습니다.

- 의미 있는 HTTP 관찰 결과를 최대한 많이 수집한다.
- 수집한 관찰 결과를 구조화된 feature로 변환한다.
- 먼저 결정론적인 룰 기반 로직으로 분류한다.
- replay, validation, deduplication으로 노이즈를 줄인다.
- LLM은 주 탐지 엔진이 아니라 보조 레이어로만 사용한다.

이 문서는 현재 코드 기준으로 다음 내용을 설명합니다.

- 크롤링이 어떻게 동작하는지
- 요청 계획을 어떻게 세우는지
- 룰 기반 탐지가 무엇을 찾는지
- LLM이 어디에서 개입하는지
- finding이 어떻게 검증, 병합, 저장되는지

## 1. 이 스캐너가 잘하는 영역

현재 스캐너가 상대적으로 강한 영역은 다음과 같습니다.

- 정보 노출
  - 상세 에러 메시지
  - 스택 트레이스
  - 데이터베이스 에러 노출
  - 내부 IP 노출
  - 프레임워크 및 버전 정보 노출
  - `phpinfo` 페이지 노출
  - 설정 파일, 백업 파일, 로그 파일 노출
  - 디렉터리 리스팅
  - 인증 후에만 보이는 차등 정보 노출
- 보안 설정 오류
  - 보안 헤더 누락
  - 취약한 쿠키 속성
  - 안전하지 않은 전송 보안 동작
  - 일부 위험 HTTP 메서드 노출

이 도구는 브라우저 자동화 프레임워크보다는 HTTP 증거 기반 탐지에 더 초점을 둡니다. 목표는 원시 HTTP 증거로부터 재현 가능한 finding을 만드는 것입니다.

## 2. 주요 진입점

주요 런타임 흐름은 다음 파일에서 시작합니다.

- [agent/agent/__main__.py](agent/agent/__main__.py)
- [agent/agent/runtime/scan_runtime.py](agent/agent/runtime/scan_runtime.py)
- [agent/agent/runtime/scan_engine.py](agent/agent/runtime/scan_engine.py)

고수준 실행 흐름은 아래와 같습니다.

1. CLI 인자와 환경변수를 파싱한다.
2. `out/<target>/<run_id>/` 아래 실행 디렉터리를 만든다.
3. 익명 상태로 엔드포인트를 탐색한다.
4. 자격 증명 또는 수동 세션 정보가 있으면 인증 상태를 구성한다.
5. 인증 상태에서 추가 탐색과 authenticated business probe를 수행한다.
6. 발견한 엔드포인트로 static request plan을 만든다.
7. 계획된 요청을 실행하고 raw 캡처를 저장한다.
8. 응답으로부터 feature를 추출한다.
9. 룰 기반 signal을 생성한다.
10. signal을 candidate finding으로 변환한다.
11. validation, verification, merge를 거쳐 최종 finding으로 정리한다.
12. `results.json`, `raw/`, `findings/`, `debug/`, `live/`, `report/`를 생성한다.

## 3. 출력 구조

각 스캔 결과는 기본적으로 아래 경로에 저장됩니다.

- `out/<target-name>/<run_id>/`

중요한 하위 디렉터리는 다음과 같습니다.

- `raw/`
  - 실행된 각 요청의 JSON 원본
- `findings/confirmed/`
- `findings/informational/`
- `findings/false_positive/`
- `debug/`
  - candidate signal과 디버깅용 중간 산출물
- `live/`
  - 진행 중 증분 업데이트되는 finding stream
- `report/`
  - 요약 보고서

`results.json`의 주요 최상위 키는 아래와 같습니다.

- `metadata`
- `raw_index`
- `findings_confirmed`
- `findings_informational`
- `findings_false_positive`
- `candidate_signals`
- `scan_diagnostics`

## 4. 크롤링과 엔드포인트 탐색

주요 크롤러:

- [agent/agent/crawler.py](agent/agent/crawler.py)

이 크롤러는 완전한 브라우저 크롤러가 아닙니다. 유용한 URL과 입력점을 빠르게 찾기 위한 HTTP 우선형 라우트 수집기입니다.

### 4.1 익명 탐색

스캐너는 항상 익명 상태에서 탐색을 시작합니다.

탐색 입력:

- 기본 `--target`
- 선택적인 `--seed-url`
- `_spa_seed_urls()`로 확장되는 공통 seed

크롤러는 다음 위치에서 라우트를 추출합니다.

- anchor 태그
- form action
- script와 link 태그
- redirect target
- JavaScript, JSON, XML, text 응답 안의 route-like 문자열
- query string 이름
- form field 이름

각 엔드포인트에는 다음과 같은 메타데이터가 붙습니다.

- `url`
- `kind`
  - `page`, `form`, `asset_js`, `static` 등
- `score`
- `field_names`
- `query_param_names`
- `states`
  - `anonymous`, `authenticated`, 또는 둘 다

### 4.2 인증 후 탐색

인증이 성립하면 인증된 세션으로 두 번째 탐색을 수행합니다.

관련 모듈:

- [agent/agent/runtime/auth_runtime.py](agent/agent/runtime/auth_runtime.py)
- [agent/agent/runtime/scan_runtime.py](agent/agent/runtime/scan_runtime.py)

이 단계가 중요한 이유는 다음과 같습니다.

- 익명 크롤링만으로는 business page나 내부 API를 놓치기 쉽다.
- 인증 후 크롤링에서 추가 라우트가 드러난다.
- 차등 정보 노출 탐지를 위해 익명/인증 응답 쌍이 필요하다.

인증된 엔드포인트는 다음에서 수집됩니다.

- 인증 후 재크롤링 결과
- 인증 landing page 문맥
- 로그인 처리 중 수집된 auth snapshot

### 4.3 앱 스코프 제한

스캐너는 같은 origin의 모든 URL을 무한정 요청하지 않습니다. 아래 로직으로 앱 스코프를 좁힙니다.

- `derive_allowed_app_prefixes()`
- `filter_endpoints_by_app_scope()`
- `filter_request_specs_by_app_scope()`

스코프는 주로 다음을 기준으로 결정됩니다.

- target
- authenticated landing URL
- seed URL

SPA 대상에는 중요한 예외가 있습니다.

- 인증 shell이 `/admin` 아래에 있고
- 실제 JavaScript bundle이 `/static/js/...`에서 제공되는 경우

same-origin JS bundle은 scope 안에 남겨서 client bundle disclosure 검사가 pruning으로 사라지지 않도록 합니다.

### 4.4 Scan Profile

스캔 성향은 아래 파일에서 조정됩니다.

- [agent/agent/runtime/scan_profile.py](agent/agent/runtime/scan_profile.py)

지원 프로파일:

- `balanced`
  - 일반 기본값
- `spa_auth_heavy`
  - SSIT처럼 인증 의존도가 높은 SPA/API 타깃에 적합
- `server_html_broad`
  - NDA처럼 HTML breadth가 중요한 타깃에 적합

프로파일은 다음에 영향을 줍니다.

- endpoint bucket 제한
- pruning 동작
- JS bundle 보존 정도
- 어떤 경로를 method-heavy 타깃으로 볼지

## 5. 요청 계획

주요 planner:

- [agent/agent/planning/probes.py](agent/agent/planning/probes.py)

각 요청은 `RequestSpec`으로 표현됩니다.

중요한 `RequestSpec` 필드:

- `name`
- `method`
- `url`
- `headers`
- `body`
- `family`
- `mutation_class`
- `auth_state`
- `replay_key`
- `expected_signal`
- `comparison_group`

### 5.1 Static Plan

Static probe 계획은 두 단계로 만들어집니다.

1. `prepare_discovered_endpoints()`가 pruning된 엔드포인트 목록을 만든다.
2. `_build_static_plan_from_endpoints()`가 probe intensity를 정하고 `build_probe_plan()`을 호출한다.

대표 intensity:

- `static`
- `light`
- `medium`
- `full`

강도는 다음에 따라 달라집니다.

- endpoint score
- path 형태
- endpoint kind
- scan profile

### 5.2 주요 probe family

스캐너는 단순 GET만 보내지 않습니다. 비교 가능한 여러 family를 사용합니다.

- `baseline`
  - `baseline_get`
  - `baseline_query_session`
  - `baseline_follow_get`
- `comparison`
  - not-found path mutation
  - benign query mutation
  - path encoding variation
- `default_resource`
  - config, backup, log, debug, `phpinfo` probe
- `directory_behavior`
  - directory listing 점검
- `header_behavior`
  - `X-Forwarded-*`, `Forwarded` variation
- `method_behavior`
  - `OPTIONS`, `PROPFIND`, `PATCH` 등
- `authenticated_business_probe`
  - 인증된 business route에 대한 GET

많은 finding은 아래 비교에서 나옵니다.

- baseline vs mutated request
- anonymous vs authenticated response
- 일반 페이지 vs resource/debug/error path

## 6. 인증 모델

인증은 두 가지 주요 방식을 지원합니다.

- 폼 로그인
  - `--auth-username`
  - `--auth-password`
- 수동 인증 세션 재사용
  - `MANUAL_AUTH_COOKIE`
  - `MANUAL_AUTH_HEADERS`

관련 파일:

- [agent/agent/runtime/auth_runtime.py](agent/agent/runtime/auth_runtime.py)
- [agent/agent/runtime/manual_auth.py](agent/agent/runtime/manual_auth.py)

### 6.1 수동 인증 헤더 형식

`MANUAL_AUTH_HEADERS`는 현재 아래 구분자를 지원합니다.

- `|||`
- `||`
- 줄바꿈

예시:

```bash
-e MANUAL_AUTH_HEADERS=$'Authorization: Bearer ...|||Origin: http://host|||Referer: http://host/'
```

### 6.2 인증 상태 손실 감지

인증된 스캔 중 세션이 사실상 아래 상태로 돌아갔는지 감지합니다.

- 로그인 페이지
- 외부 SSO redirect
- session-expired response
- 401, 403, 407 같은 강한 auth-required 신호

현재 로직은 보수적으로 동작합니다. `login`, `password` 같은 단어만 있다고 바로 auth-loss로 보지 않도록 설계되어 있습니다.

## 7. Feature Extraction

주요 feature 추출은 아래 파일에서 수행됩니다.

- [agent/agent/analysis/features.py](agent/agent/analysis/features.py)

이 단계는 raw HTTP 응답을 구조화된 관찰값으로 바꿉니다.

대표 feature:

- status code와 redirect 정보
- content type과 response kind
- banner header
- cookie 관찰값
- allowed methods
- stack trace
- file path
- internal IP
- DB error
- runtime error
- framework hint
- debug hint
- directory listing hint
- default file hint
- `phpinfo` indicator/value
- config-style key/value
- auth/session loss indicator

이 단계는 아직 finding 단계가 아닙니다. 스캐너는 의도적으로 아래를 분리합니다.

- 무엇을 관찰했는가
- 무엇을 보고해야 하는가

## 8. 룰 기반 탐지

HTTP signal builder는 주로 아래 파일에 있습니다.

- [agent/agent/http/http_signal_builder.py](agent/agent/http/http_signal_builder.py)
- [agent/agent/http/http_policy_classifier.py](agent/agent/http/http_policy_classifier.py)
- [agent/agent/http/http_disclosure_classifier.py](agent/agent/http/http_disclosure_classifier.py)
- [agent/agent/http/http_resource_classifier.py](agent/agent/http/http_resource_classifier.py)
- [agent/agent/http/disclosure_enrichment.py](agent/agent/http/disclosure_enrichment.py)

이 모듈들은 feature를 rule-based signal로 바꿉니다.

대표 finding type:

- `HTTP_ERROR_INFO_EXPOSURE`
- `HTTP_SYSTEM_INFO_EXPOSURE`
- `HTTP_CONFIG_FILE_EXPOSURE`
- `PHPINFO_EXPOSURE`
- `DIRECTORY_LISTING_ENABLED`
- `COOKIE_HTTPONLY_MISSING`
- `COOKIE_SECURE_MISSING`
- `COOKIE_SAMESITE_MISSING`
- `CLICKJACKING`
- `HSTS_MISSING`
- `CONTENT_TYPE_SNIFFING`

### 8.1 탐지 기준을 이해하는 순서

코드를 이해할 때는 대략 아래 순서로 보면 편합니다.

1. 응답 정책 문제
   - 보안 헤더 누락
   - 약한 cookie 속성
   - transport/security policy 문제
2. 직접적인 HTTP 노출
   - config file
   - `phpinfo`
   - directory listing
   - setup/debug/default resource
3. body 기반 정보 노출
   - internal IP
   - stack trace
   - DB error
   - framework/version/runtime detail
4. 비교 기반 차등 노출
   - anonymous vs authenticated
   - baseline vs mutation

### 8.2 예시

- `HTTP_ERROR_INFO_EXPOSURE`
  - stack trace, SQL error, constraint name, local file path
- `HTTP_SYSTEM_INFO_EXPOSURE`
  - internal IP, framework hint, server header, runtime detail
- `HTTP_CONFIG_FILE_EXPOSURE`
  - 외부 접근 가능한 config/backup file
- `DIRECTORY_LISTING_ENABLED`
  - deterministic한 directory index 노출
- `RISKY_HTTP_METHODS_ENABLED`
  - 민감 메서드가 허용되거나 실제 동작하는 증거

## 9. Candidate 생성, Validation, Verification

Signal은 아직 최종 finding이 아닙니다.

관련 모듈:

- [agent/agent/candidates.py](agent/agent/candidates.py)
- [agent/agent/runtime/candidate_verifier.py](agent/agent/runtime/candidate_verifier.py)
- [agent/agent/runtime/candidate_finalizer.py](agent/agent/runtime/candidate_finalizer.py)
- [agent/agent/analysis/verification_policy.py](agent/agent/analysis/verification_policy.py)
- [agent/agent/analysis/validation_policy.py](agent/agent/analysis/validation_policy.py)
- [agent/agent/findings/store.py](agent/agent/findings/store.py)

### 9.1 Candidate Generation

Candidate finding은 대체로 아래 정보를 가집니다.

- `type`
- `title`
- `severity`
- `cwe`
- `owasp`
- `evidence`
- `verification_strategy`
- `exposed_information`

### 9.2 Validation

Validation 단계는 약하거나 오해의 소지가 있는 candidate를 제거하거나 informational로 낮춥니다.

대표 사례:

- keyword만 있는 generic match
- binary garbage를 file path로 잘못 읽은 경우
- 의미 있는 노출 없이 source marker만 있는 경우
- 가치가 낮은 약한 system-info 신호

### 9.3 Verification

Verification은 finding 종류에 따라 다르게 수행됩니다.

예:

- deterministic single-observation confirmation
- rule-based detector confirmation
- repeated reproduction
- differential replay
- method verification
  - PUT upload retrieval check
  - DELETE 이후 absence verification

최종 finding에는 다음이 붙습니다.

- `verification.verdict`
- `verification.reason`

## 10. Differential Disclosure

차등 정보 노출 로직은 주로 아래 파일에 있습니다.

- [agent/agent/runtime/scan_results.py](agent/agent/runtime/scan_results.py)
- [agent/agent/runtime/scan_runtime.py](agent/agent/runtime/scan_runtime.py)

동작 순서:

1. 인증된 세션으로 먼저 스캔한다.
2. 정보 노출과 관련된 route를 anonymous client로 다시 요청한다.
3. 양쪽 응답에서 구조화된 disclosure value를 추출한다.
4. `authenticated_values - anonymous_values`를 계산한다.
5. 인증 후에만 의미 있는 값이 생기면 differential finding을 만든다.

현재 differential extraction이 보는 값 예시는 다음과 같습니다.

- `phpinfo` 데이터
- config key/value
- runtime error
- local file path
- internal IP
- 민감 사용자 필드
  - email
  - phone
  - login IP
  - last login
  - employee ID
  - department
  - role
  - position
  - password-hash 또는 encrypted-password metadata

중요한 differential subtype:

- `authenticated_phpinfo_disclosure`
- `authenticated_config_disclosure`
- `authenticated_profile_disclosure`
- `authenticated_credential_metadata_disclosure`
- `authenticated_diagnostic_disclosure`

## 11. False Positive 제어

노이즈 감소는 여러 단계에 나뉘어 있습니다. 한 군데에서 크게 필터링하지 않습니다.

### 11.1 Discovery Pruning

- low-value endpoint는 우선순위를 낮추거나 제거
- session-destructive route는 제외
- static asset 비중 제한

### 11.2 Feature Sanitization

- path처럼 보이는 노이즈 정리
- 가치 낮은 internal IP match 필터링
- binary/garbled text가 evidence가 되지 않도록 방지

### 11.3 Classifier Threshold

- source marker만으로는 바로 finding이 되지 않음
- 약한 DB error는 meaningful detail이 없으면 suppress
- generic auth-loss wording만으로는 세션 만료로 보지 않음

### 11.4 Merge And Dedupe

Stable identity key를 사용해 반복 관찰을 병합합니다.

예:

- host-wide banner finding
- canonical URL normalization
- 같은 route의 반복 disclosure

현재 merge 로직은 internal IP를 포함한 body disclosure finding이 header-only supporting signal보다 우선되도록 보정되어 있습니다.

## 12. LLM은 어디에 붙는가

의도한 구조는 다음과 같습니다.

- 룰 기반 로직이 재현 가능한 탐지를 담당한다.
- LLM은 우선순위, 문구, 약한 evidence 정리에 보조적으로 사용된다.

주요 LLM 관련 파일:

- [agent/agent/llm_client.py](agent/agent/llm_client.py)
- [agent/agent/planning/llm_probe_planner.py](agent/agent/planning/llm_probe_planner.py)
- [agent/agent/reporting/report_generator.py](agent/agent/reporting/report_generator.py)

환경변수:

- `LLM_MODE`
- `LLM_PROBE_PLANNER_MODE`
- `LLM_REPORT_MODE`

### 12.1 룰 기반이 담당하는 일

- 크롤링
- 요청 계획
- 응답 파싱
- feature extraction
- deterministic classification
- replay verification
- merge와 dedupe
- 최종 evidence assembly

### 12.2 LLM이 담당하는 일

활성화된 경우 LLM은 주로 아래 역할을 맡습니다.

1. evidence review
   - 약한 disclosure evidence 정리
   - severity, CWE, finding 문구 보조
2. 추가 probe planning
   - midpoint/final 단계에서 추가 `RequestSpec` 제안
3. report assistance
   - 사람이 읽기 쉬운 요약 생성 보조

중요한 점:

- LLM이 꺼져 있어도 스캐너는 동작한다.
- 핵심 탐지 파이프라인은 여전히 룰 기반이다.

## 13. 중요한 런타임 파라미터

자주 조정하는 값:

- `TIMEOUT_SECONDS`
- `RETRIES`
- `REQUEST_BUDGET`
- `MAX_ENDPOINTS`
- `CRAWL_DEPTH`
- `CRAWL_MAX_PAGES`
- `CRAWL_INCLUDE_JS_PATHS`
- `AUTH_SESSION_BUDGET_SECONDS`
- `AUTHENTICATED_BUSINESS_PROBE_MAX_TARGETS`
- `AUTHENTICATED_HIGH_VALUE_METHOD_PROBE_MAX_TARGETS`
- `SCAN_PROFILE`
- `PRIORITY_JS_ENDPOINTS`
- `CLIENT_BUNDLE_PROBE_MAX_TARGETS`
- `CLIENT_BUNDLE_PROBE_INTENSITY`

운영 팁:

- 인증 의존도가 높은 SPA/API 타깃에는 `SCAN_PROFILE=spa_auth_heavy`
- HTML breadth가 중요한 타깃에는 `SCAN_PROFILE=server_html_broad`
- 가능하면 realistic한 `--seed-url`을 제공
- authenticated business route를 seed에 넣을수록 차등 노출 탐지가 강해짐

## 14. 현재 한계

- 완전한 브라우저 런타임을 흉내내지는 못한다.
- OTP 갱신 같은 복잡한 로그인 갱신 흐름은 제한적이다.
- 차등 정보 노출은 실제로 도달한 authenticated route 품질에 크게 좌우된다.
- 엔터프라이즈 타깃에서는 seed URL 품질의 영향이 크다.

## 15. 실무 사용 팁

내부 시스템 테스트 시 권장 사항:

- 최소 한 개 이상의 실제 authenticated session 제공
- 실제 business URL을 `--seed-url`로 넣기
- `profile`, `detail`, `view`, `info`, `member`, `account`, `mypage` 계열 route를 포함하기
- 가능하면 anonymous와 authenticated 응답을 함께 비교하기

Finding을 볼 때 가장 중요한 필드:

- `type`
- `title`
- `visibility_scope`
- `exposure_context`
- `severity`
- `cwe`
- `verification`

이 필드들이 빠르게 답해주는 질문은 다음과 같습니다.

- 무엇이 노출되었는가
- 어디에서 관찰되었는가
- 누가 볼 수 있는가
- 증거가 얼마나 강한가

## 16. 요약

`public_http_agent`는 단순한 키워드 grep 스크립트가 아닙니다.

이 도구는 다음 파이프라인으로 이해하면 됩니다.

- HTTP 관찰 기반 route discovery
- 비교 가능한 probe planning
- 구조화된 feature extraction
- 룰 기반 classification
- verification과 deduplication
- 필요할 때만 LLM을 보조 레이어로 사용

이 조합 덕분에 finding이 읽기 쉽고, 재현 가능하며, 내부 보안 검토에 바로 활용 가능한 형태로 정리됩니다.
