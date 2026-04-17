# public_http_agent

HTTP 기반 DAST agent입니다.  
이 프로젝트는 웹 애플리케이션에 대해 HTTP 요청, 오류 유발, 기본 리소스 탐색, 헤더/쿠키 점검, 일부 재현 검증을 수행하여 다음 계열의 이슈를 탐지합니다.

- 정보 노출
  - 설정 파일 노출
  - phpinfo 노출
  - 에러 응답 기반 내부 정보 노출
  - 서버/프레임워크/내부 IP/버전 노출
- 보안 설정 미흡
  - 보안 헤더 누락
  - 쿠키 속성 미흡
  - HTTPS redirect/HSTS 누락
  - 위험한 HTTP method 노출
  - 일부 access control / protected resource 노출

이 README는 "이 코드가 어떤 흐름으로 동작하는지"를 잘 모르는 팀원이 빠르게 파악할 수 있도록, 코드 기준으로 탐지 흐름과 평가 기준을 설명하는 명세서입니다.

## 1. 한눈에 보는 구조

실제 Python 패키지는 `agent/agent/` 아래에 있습니다.

- `agent/agent/__main__.py`
  - CLI 진입점
- `agent/agent/runtime/`
  - 전체 스캔 오케스트레이션
- `agent/agent/crawler.py`
  - 크롤링 및 endpoint discovery
- `agent/agent/planning/`
  - probe plan 생성
- `agent/agent/http/`
  - HTTP response classification
- `agent/agent/candidates.py`
  - signal -> candidate 변환
- `agent/agent/analysis/`
  - feature extraction, validation, verification policy
- `agent/agent/findings/`
  - finding identity, merge, dedupe, persistence
- `agent/agent/reporting/`
  - 결과 리포트 생성
- `agent/agent/llm_client.py`
  - 선택적 LLM 활용

큰 흐름은 아래와 같습니다.

1. target과 seed URL을 받음
2. crawler가 endpoint를 수집함
3. planning이 endpoint별 probe plan을 만듦
4. runtime이 실제 HTTP 요청을 실행하고 raw를 저장함
5. analysis/http classifier가 응답을 feature와 signal로 변환함
6. signal이 candidate finding으로 승격됨
7. validation/verification이 confirmed vs informational vs false positive를 판단함
8. findings가 merge/dedupe를 수행함
9. reporting이 compact/debug/report 결과를 저장함

## 2. 실행 진입점

진입점은 [agent/agent/__main__.py](agent/agent/__main__.py) 입니다.

여기서:

- `--target`
- `--target-name`
- `--out-dir`
- `--seed-url`
- optional auth 인자

를 받아서 [agent/agent/runtime/scan_runtime.py](agent/agent/runtime/scan_runtime.py)의 `run_scan()`으로 넘깁니다.

즉 실제 스캔의 메인 루프는 `run_scan()`입니다.

## 3. 전체 스캔 흐름

`run_scan()`이 수행하는 큰 단계는 아래와 같습니다.

1. 출력 디렉터리 준비
2. anonymous crawl 수행
3. 필요시 authenticated session 준비
4. endpoint별 probe plan 생성
5. 요청 실행 및 raw 저장
6. response -> feature -> signal -> candidate 변환
7. candidate validation / reproduce verify
8. finding merge / bucket 정리
9. summary / results.json / report 생성

이 중 핵심은 다음 두 함수입니다.

- [agent/agent/runtime/scan_runtime.py](agent/agent/runtime/scan_runtime.py)
  - 스캔 전체 orchestration
- [agent/agent/runtime/scan_engine.py](agent/agent/runtime/scan_engine.py)
  - plan 처리, candidate finalization, reproduce verification 연결

## 4. Crawl 과정

크롤링의 핵심은 [agent/agent/crawler.py](agent/agent/crawler.py)의 `discover_endpoints()` 입니다.

### 4.1 crawl 목표

목표는 "탐지할 수 있는 target URL 후보를 최대한 많이 수집"하는 것입니다.  
단, 모든 URL을 무작정 다 저장하지는 않고, 같은 origin 범위 안에서 상대적으로 의미 있는 endpoint를 우선 수집합니다.

### 4.2 수집 방식

crawler는 크게 네 가지 경로로 endpoint를 모읍니다.

- HTML 링크/폼 파싱
  - `a`, `form`, `script`, 각종 URL 속성
- JS/본문 문자열 추출
  - JS 문자열 안의 route-like path
- 헤더 기반 추출
  - redirect/location, 일부 link 계열 힌트
- text-like response 확장 파싱
  - JSON/XML/text에서도 URL-like 후보 수집

또한 SPA/일반 앱에서 자주 보이는 공통 seed path도 일부 고려합니다.

예:

- `/api`
- `/rest`
- `/graphql`
- `/robots.txt`
- `/.well-known/security.txt`

### 4.3 endpoint 품질 판단

crawler는 endpoint마다 메타데이터를 붙입니다.

- `kind`
  - page, form, static, asset_js 등
- `score`
  - 얼마나 고가치 endpoint처럼 보이는지
- `states`
  - anonymous / authenticated
- `field_names`
  - form/input 파라미터 후보

이 score는 이후 probe intensity 결정에 사용됩니다.

### 4.4 low-value 필터링

전부 다 probe하지 않기 위해 low-value filtering을 수행합니다.

주로 다음이 저우선순위입니다.

- 정적 리소스
  - css, image, font, media, pdf 등
- 문서성/설명성 파일
  - readme, changelog, help, faq, docs
- logout 같은 session destructive endpoint

이 필터링 결과는 `run_scan()`에서:

- discovered endpoints before pruning
- after low-value filtering
- after pruning

형태로 로그에 남습니다.

## 5. 탐지 target URL 수집과 probe 생성 방식

endpoint가 수집되면 [agent/agent/planning/probes.py](agent/agent/planning/probes.py)의 `RequestSpec` 기반 probe plan으로 바뀝니다.

### 5.1 RequestSpec

`RequestSpec`는 실제 요청 단위입니다.

포함되는 정보:

- method
- url
- headers
- body
- family
- mutation_class
- target_param
- target_header
- expected_signal
- comparison_group
- auth_state

즉 "왜 이 요청을 보내는지"까지 메타데이터로 같이 들고 갑니다.

### 5.2 probe 종류

probe는 단일 종류가 아닙니다. 대략 아래 축으로 나뉩니다.

- baseline probe
  - 일반 GET/HEAD
- comparison probe
  - notfound, query mutation, path mutation
- default resource probe
  - config, phpinfo, debug, backup, log-like resource
- directory behavior probe
  - directory listing / static path
- header behavior probe
  - X-Forwarded-* 등 헤더 변화
- method behavior probe
  - OPTIONS/TRACE/PUT/DELETE 등
- replay probe
  - access control / protected resource 확인

이렇게 probe를 다양하게 보내는 이유는 "정상 응답과 변형 응답의 차이"를 보고 보안 이슈를 더 잘 식별하기 위해서입니다.

## 6. Response 처리: feature -> signal -> candidate

### 6.1 feature extraction

응답이 오면 먼저 [agent/agent/analysis/features.py](agent/agent/analysis/features.py)의 `extract_features()`가 response에서 feature를 뽑습니다.

예를 들면:

- status code
- content type
- body text
- stack trace 조각
- file path
- DB error 문자열
- phpinfo indicator/value
- config extracted values
- internal IP
- header disclosure
- set-cookie 관련 정보
- auth/session-loss 징후

여기서 중요한 점은:

- feature는 아직 취약점이 아닙니다.
- "응답에서 관찰된 구조화된 단서"입니다.

### 6.2 HTTP classification

그 다음 [agent/agent/http/classifier.py](agent/agent/http/classifier.py)의 `collect_http_signals()`가 feature를 보고 signal을 생성합니다.

signal 생성은 하위 classifier로 나뉩니다.

- `http_policy_classifier.py`
  - 보안 헤더, 쿠키, CORS, transport
- `http_disclosure_classifier.py`
  - error/body/header 기반 정보 노출
- `http_resource_classifier.py`
  - config/phpinfo/default resource/log exposure
- `disclosure_enrichment.py`
  - detector 기반 추가 disclosure signal

### 6.3 signal의 의미

signal은 "rule-based classifier가 의미 있다고 본 관찰 결과"입니다.

예:

- `PHPINFO_EXPOSURE`
- `HTTP_CONFIG_FILE_EXPOSURE`
- `HTTP_ERROR_INFO_EXPOSURE`
- `HTTP_SYSTEM_INFO_EXPOSURE`
- `CLICKJACKING`
- `COOKIE_SECURE_MISSING`

하지만 signal도 아직 최종 finding은 아닙니다.  
이후 candidate로 올라가고, 검증/정제/병합을 거칩니다.

### 6.4 candidate 생성

[agent/agent/candidates.py](agent/agent/candidates.py)의 `generate_candidates()`가 signal들을 그룹핑하고 candidate finding으로 변환합니다.

이 단계에서는:

- 같은 유형의 signal 묶기
- evidence 병합
- title/cwe/owasp/severity 등 기본 finding 스키마 부여

를 수행합니다.

## 7. 어떤 것을 취약점으로 판별하는가

이 프로젝트는 모든 단서를 바로 "취약점"으로 보지 않습니다.  
핵심은 **가치 있는 노출인지**, **재현 가능한 설정 문제인지**, **실제 증거가 충분한지** 입니다.

### 7.1 정보 노출 계열

주요 confirmed 대상:

- `HTTP_CONFIG_FILE_EXPOSURE`
  - 실제 config 값, DB credential, secret-like value가 노출
- `PHPINFO_EXPOSURE`
  - phpinfo page 전체가 노출
- `HTTP_ERROR_INFO_EXPOSURE`
  - 실제 stack trace / uncaught exception / DB error / local path 등
- `HTTP_SYSTEM_INFO_EXPOSURE`
  - 내부 IP, 배너, 시스템 정보
  - 다만 보통 informational로 유지되는 경우가 많음

### 7.2 보안 설정 미흡 계열

주요 대상:

- `CLICKJACKING`
- `CSP_MISSING`
- `CONTENT_TYPE_SNIFFING`
- `REFERRER_POLICY_MISSING`
- `PERMISSIONS_POLICY_MISSING`
- `COOKIE_SECURE_MISSING`
- `COOKIE_HTTPONLY_MISSING`
- `COOKIE_SAMESITE_MISSING`
- `HTTPS_REDIRECT_MISSING`
- `HSTS_MISSING`

### 7.3 단서와 취약점의 차이

중요한 설계 포인트는 다음입니다.

- `<?php`
- `db_password`
- `database`
- 단순 `Fatal error`
- 짧은 `sqlite3.` 조각

같은 것은 그 자체만으로는 가치 있는 취약점이라고 보기 어렵습니다.

따라서 현재 코드는:

- marker-only
- low-value stack trace
- weak db error
- generic version disclosure

를 `supporting_signal` 또는 informational로 강등하는 방향을 가지고 있습니다.

## 8. 오탐은 어떻게 거르는가

오탐 제거는 한 군데가 아니라 여러 단계에서 수행됩니다.

### 8.1 crawl 단계

- static asset 제외
- 문서성 endpoint 저우선순위화
- logout 같은 파괴적 endpoint 제외

### 8.2 classifier 단계

[agent/agent/http/classifier.py](agent/agent/http/classifier.py) 와 하위 classifier는 다음을 강하게 체크합니다.

- auth redirect / login page / SSO page인지
- generic 404 template인지
- static response인지
- 실제 노출값이 있는지, 아니면 marker-only인지
- resource probe가 실제 취약점 페이지가 아니라 일반 notfound/error template인지

### 8.3 validation 단계

[agent/agent/analysis/validation_policy.py](agent/agent/analysis/validation_policy.py) 에서:

- ambiguous finding severity cap
- low-value signal downgrade
- deterministic vs ambiguous 분기

를 수행합니다.

예:

- file-path only -> Medium 이하
- richer DB error / stack trace -> High 가능
- weak signal -> informational

### 8.4 verification 단계

[agent/agent/runtime/candidate_verifier.py](agent/agent/runtime/candidate_verifier.py) 와 verification policy가 일부 finding에 대해 재현/확인을 수행합니다.

예:

- access control replay
- protected resource exposure
- session/control 관련 검증

### 8.5 merge / dedupe 단계

[agent/agent/findings/store.py](agent/agent/findings/store.py), [agent/agent/findings/identity.py](agent/agent/findings/identity.py), [agent/agent/http/http_signal_postprocessing.py](agent/agent/http/http_signal_postprocessing.py) 에서:

- stronger finding이 weaker finding을 덮기
- host-wide banner dedupe
- phpinfo duplicate 제거
- synthetic probe URL 정규화

를 수행합니다.

즉 오탐 제거는 "하나의 if문"이 아니라, 수집 -> 분류 -> 검증 -> 병합 전 과정에 분산되어 있습니다.

## 9. 평가 기준

현재 프로젝트는 크게 아래 기준으로 finding을 평가합니다.

### 9.1 evidence quality

좋은 evidence:

- 실제 stack trace
- 실제 file path
- 실제 DB error
- 실제 config key-value
- 실제 phpinfo extracted value
- 실제 banner/version value

약한 evidence:

- 단순 marker
- 잘린 문자열
- generic error title
- common keyword only

### 9.2 repeatability

한 번 우연히 보인 값보다:

- 여러 probe에서 반복되는지
- baseline과 mutation의 차이가 일관적인지

를 더 신뢰합니다.

### 9.3 scope

finding은 대략 아래 범위 중 하나로 다룹니다.

- host-wide
- route-specific
- cookie-specific
- resource-specific

이 scope는 stable key, dedupe, report grouping에 직접 영향을 줍니다.

### 9.4 deterministic vs ambiguous

[agent/agent/findings/types.py](agent/agent/findings/types.py) 및 validation 정책은 finding을 대략 아래처럼 취급합니다.

- deterministic
  - 보안 헤더 누락, cookie secure missing 등
- ambiguous
  - 정보 노출, error disclosure, system info disclosure 등

ambiguous finding은 더 많은 evidence와 검증을 요구합니다.

## 10. Rule-based와 LLM은 어디에 어떻게 활용하는가

이 프로젝트의 기본 철학은:

- **탐지의 뼈대는 rule-based**
- **LLM은 후보 가치 판단, 정규화, 설명 보강에 사용**

입니다.

### 10.1 rule-based가 하는 일

rule-based는 항상 핵심입니다.

- endpoint 수집
- probe 생성
- response parsing
- feature extraction
- signal generation
- base severity
- candidate validation
- reproduce verification
- dedupe / merge

즉 LLM이 없어도 스캐너는 동작합니다.

### 10.2 LLM이 쓰이는 지점

현재 코드 기준으로 LLM은 선택적으로 세 군데에서 사용됩니다.

1. candidate judgement
   - [agent/agent/runtime/scan_runtime.py](agent/agent/runtime/scan_runtime.py)의 `llm_judge_if_enabled()`
2. probe planning
   - [agent/agent/planning/llm_probe_planner.py](agent/agent/planning/llm_probe_planner.py)
3. report generation
   - [agent/agent/reporting/report_generator.py](agent/agent/reporting/report_generator.py)

그리고 실제 client는 [agent/agent/llm_client.py](agent/agent/llm_client.py) 가 담당합니다.

### 10.3 LLM on/off 제어

환경변수:

- `LLM_MODE`
- `LLM_PROBE_PLANNER_MODE`
- `LLM_REPORT_MODE`

로 제어합니다.

즉:

- `LLM off`
  - rule-based only + heuristic fallback
- `LLM on`
  - rule-based 결과를 바탕으로 LLM judgement/normalization/report 강화

### 10.4 왜 이런 구조인가

이 구조의 장점은 다음과 같습니다.

- LLM이 없어도 기본 동작 보장
- 보안팀이 rule을 추적 가능
- 재현성과 감사 가능성 확보
- LLM은 설명 보강 및 애매한 evidence triage에 집중

## 11. 인증 / 세션 / SSO 고려

이 프로젝트는 일반 로그인뿐 아니라 "수동으로 세션 쿠키를 주입해서 스캔하는 환경"도 고려합니다.

관련 코드는 주로:

- [agent/agent/runtime/auth_runtime.py](agent/agent/runtime/auth_runtime.py)
- [agent/agent/http/http_session.py](agent/agent/http/http_session.py)
- [agent/agent/analysis/features.py](agent/agent/analysis/features.py)

입니다.

현재 고려하는 문제:

- SSO redirect
- login page로 튕김
- external auth transition
- session expired
- auth cookie는 넣었지만 실제로는 권한이 없는 상태

즉 "응답을 받았으니 탐지 가능하다"가 아니라,  
"이 응답이 실제 인증된 앱 응답인지"를 먼저 보려는 흐름이 들어가 있습니다.

## 12. 결과물 구조

실행 결과는 `out/<target>/<run_id>/` 아래에 저장됩니다.

주요 산출물:

- `raw/`
  - 각 요청/응답 원본
- `findings/confirmed`
  - confirmed finding
- `findings/informational`
  - informational finding
- `findings/false_positive`
  - false positive
- `debug/`
  - debug finding, candidate signal
- `results.json`
  - 전체 요약 결과

`findings/*.json`은 compact view이고, `debug/...debug.json`은 더 많은 내부 정보가 들어갑니다.

## 13. 현재 프로젝트의 특징과 한계

### 강점

- HTTP 기반 탐지 흐름이 명확함
- rule-based core가 잘 분리되어 있음
- 정보 노출/헤더/쿠키/에러 응답/리소스 노출을 함께 다룸
- LLM이 없어도 regression test 가능
- raw evidence와 finding이 연결되어 디버깅 가능

### 현재 한계

- 브라우저 상호작용 없이 숨겨진 client-side route는 한계가 있음
- `Set-Cookie`를 실제로 못 보면 `HttpOnly`, `SameSite` 확정이 어려움
- generic signal과 real finding의 경계는 계속 튜닝 필요
- app 특성에 따라 representative finding merge 전략은 추가 개선 여지 있음

## 14. 로컬 DVWA 테스트

로컬 DVWA 테스트 환경이 포함되어 있습니다.

### WSL quick start

1. Docker Desktop 실행 및 WSL integration 활성화
2. WSL에서 repository 진입
3. 필요하면 DVWA source clone

```bash
chmod +x scripts/setup-dvwa.sh
./scripts/setup-dvwa.sh
```

4. 로컬 DVWA 스캔 실행

```bash
chmod +x run-dvwa.sh
./run-dvwa.sh
```

이 흐름은:

- `dvwa-db`
- `dvwa`
- `dast-agent`

를 함께 띄우고, 결과를 `./out/dvwa/` 아래에 저장합니다.

### 관련 참고

- 로컬 DVWA는 기본적으로:
  - `DISABLE_AUTHENTICATION=true`
  - `DEFAULT_SECURITY_LEVEL=low`
- `run-dvwa.sh`는 기본적으로:
  - `LLM_MODE=off`
  - `LLM_PROBE_PLANNER_MODE=off`
  - `LLM_REPORT_MODE=off`

## 15. 이 문서를 읽는 사람이 기억하면 좋은 핵심

이 프로젝트는 "웹앱에 HTTP 요청을 여러 방식으로 보내고, 그 응답의 차이와 노출된 값을 구조적으로 분석해서 finding을 만드는 rule-based DAST agent"입니다.

핵심 포인트는 아래 네 가지입니다.

1. crawl은 URL을 많이 모으기 위한 단계
2. classification은 response를 signal로 해석하는 단계
3. validation/verification은 진짜 finding인지 거르는 단계
4. LLM은 보조적이며, 탐지 핵심은 rule-based

즉 이 프로젝트를 이해하려면 아래 순서로 보면 됩니다.

1. [agent/agent/__main__.py](agent/agent/__main__.py)
2. [agent/agent/runtime/scan_runtime.py](agent/agent/runtime/scan_runtime.py)
3. [agent/agent/crawler.py](agent/agent/crawler.py)
4. [agent/agent/planning/probes.py](agent/agent/planning/probes.py)
5. [agent/agent/analysis/features.py](agent/agent/analysis/features.py)
6. [agent/agent/http/classifier.py](agent/agent/http/classifier.py)
7. [agent/agent/candidates.py](agent/agent/candidates.py)
8. [agent/agent/runtime/scan_engine.py](agent/agent/runtime/scan_engine.py)
9. [agent/agent/findings/store.py](agent/agent/findings/store.py)
10. [agent/agent/reporting/report_generator.py](agent/agent/reporting/report_generator.py)
## Diagnostic Disclosure Notes

최근 분류 로직에는 `setup/install/status/debug/info` 계열 페이지의 일반적인 diagnostic disclosure 탐지가 포함된다.

- 절대 경로 노출
- writable/upload/config directory 상태 노출
- 런타임 버전 및 서버 환경 정보 노출
- 설정 파일 위치 또는 setup check 결과 노출

이 로직은 특정 테스트베드 전용 예외가 아니라, `diagnostic page + concrete local path/permission/runtime detail` 조합을 일반 규칙으로 처리한다.

또한 planner는 위와 같은 경로에 한해 저위험 diagnostic query probe를 추가로 생성한다.

- `?verbose=true`
- `?debug=1`
- `?diagnostic=1`

목적은 기능 변경이 아니라, 이미 존재하는 진단/verbose 출력이 query flag에 따라 더 많이 드러나는지를 확인하는 것이다.
## Authenticated DVWA Test Runs

`run-dvwa.sh` supports authenticated test runs through environment variables so the same flow can be reused for cookie-based, form-based, or SSO-adjacent validation:

- `AUTH_USERNAME`
- `AUTH_PASSWORD`
- `MANUAL_AUTH_COOKIE`
- `MANUAL_AUTH_HEADERS`
- `SCANNER_EXTRA_ARGS`

Example:

```bash
AUTH_USERNAME=admin AUTH_PASSWORD=password TARGET_NAME=dvwa_auth ./run-dvwa.sh
```

For setup, installer, or diagnostic pages, disclosed filesystem paths and writable directories are reported as information disclosure even when the scanner cannot directly browse those filesystem locations over HTTP. In those cases the report now preserves the limitation explicitly: the path disclosure is meaningful, but direct follow-up access was not confirmed in-band during the scan.

