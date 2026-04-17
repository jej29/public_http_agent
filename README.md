# public_http_agent

`public_http_agent` is an HTTP-focused DAST agent for finding information disclosure and security misconfiguration issues through live requests, response comparison, and lightweight replay verification.

The scanner is designed around a simple principle:

- collect as many meaningful HTTP observations as possible
- convert them into structured features
- classify them with rule-based detectors
- reduce noise with validation, replay, and deduplication
- report only findings that have readable evidence

This document explains how the scanner works so that someone new to the project can understand the code flow, target discovery strategy, finding logic, false-positive controls, and where rule-based logic and LLM review fit in.

## Goals

The current scanner is strongest at:

- information disclosure over HTTP
  - verbose error pages
  - phpinfo exposure
  - configuration and backup file exposure
  - directory listing
  - system and environment detail leakage
  - authenticated-only differential disclosure
- security misconfiguration
  - missing security headers
  - cookie attribute weaknesses
  - insecure transport behavior
  - risky HTTP methods

The scanner works best when at least one authenticated account is available. For disclosure analysis, the long-term model is:

- anonymous vs authenticated
- authenticated user vs admin

That differential view lets us answer not only "is information exposed?" but also "who can see it?"

## Entry Points

Main entry points:

- [agent/agent/__main__.py](agent/agent/__main__.py)
- [agent/agent/runtime/scan_runtime.py](agent/agent/runtime/scan_runtime.py)
- [agent/agent/runtime/scan_engine.py](agent/agent/runtime/scan_engine.py)

High-level flow:

1. Parse CLI arguments.
2. Prepare output directories and runtime options.
3. Discover endpoints with anonymous crawling.
4. Authenticate if credentials or manual auth context are provided.
5. Build probe plans for baseline, mutations, resource checks, and authenticated business probes.
6. Execute requests and save raw captures.
7. Extract features from responses.
8. Build rule-based signals.
9. Convert signals into candidate findings.
10. Validate, verify, merge, deduplicate, and serialize findings.
11. Generate `results.json`, debug artifacts, and reports.

## Output Layout

Results are written under:

- `out/<target-name>/<run_id>/`

Important subdirectories:

- `raw/`
  - one JSON file per executed request/response
- `findings/confirmed/`
- `findings/informational/`
- `findings/false_positive/`
- `debug/`
  - candidate signal dumps and debug material
- `report/`
  - summarized report outputs

`run_id` is timestamp-based, so each scan gets its own folder.

## Crawl And Target Collection

Primary crawler:

- [agent/agent/crawler.py](agent/agent/crawler.py)

Discovery is not a full browser crawl. It is an HTTP-first crawl that focuses on extracting useful routes and inputs quickly.

Discovery sources:

- anchor and form actions from HTML
- script and body text URLs
- redirect targets
- route-like strings inside JavaScript, JSON, XML, and text-like bodies
- known seed paths such as `robots.txt`, API roots, and common app entry pages

Each discovered endpoint is tagged with metadata such as:

- endpoint kind
  - page, form, static asset, API-like, document-like
- endpoint score
  - estimated usefulness for probing
- discovered input names
  - query parameters, form field names
- states
  - anonymous, authenticated, or both

The runtime uses that metadata to decide which probes are worth sending and which low-value paths can be pruned.

## Probe Planning

Planner modules:

- [agent/agent/planning/probes.py](agent/agent/planning/probes.py)
- [agent/agent/planning/llm_probe_planner.py](agent/agent/planning/llm_probe_planner.py)

Every request is represented as a `RequestSpec` carrying:

- URL
- method
- headers
- body
- auth state
- probe family
- mutation class
- expected signal
- comparison group

Important probe families:

- baseline probes
  - plain GET, HEAD, and follow-redirect observations
- comparison probes
  - not-found mutations
  - benign query mutations
  - path encodings
- resource exposure probes
  - config files
  - backups
  - logs
  - phpinfo/debug/default resources
- directory behavior probes
  - folder routes and index behavior
- header behavior probes
  - forwarded and proxy-related variations
- authenticated business probes
  - pages only visible or reachable after login
- replay probes
  - differential anonymous vs authenticated re-requests

The planner is intentionally comparative. Many findings come from the difference between:

- baseline vs mutated request
- anonymous vs authenticated request
- normal page vs verbose/debug path

## Authentication Model

Authentication helpers:

- [agent/agent/runtime/auth_runtime.py](agent/agent/runtime/auth_runtime.py)
- [agent/agent/runtime/scan_engine.py](agent/agent/runtime/scan_engine.py)

Supported modes:

- form login using `--auth-username` and `--auth-password`
- manual session reuse using supplied cookies and headers

Why authentication matters:

- authenticated crawling exposes additional routes
- cookie findings such as `HttpOnly` and `SameSite` require observing `Set-Cookie`
- differential disclosure needs both anonymous and authenticated observations

### Auth State Loss Detection

The runtime keeps track of whether an authenticated scope appears to have fallen back to:

- login page
- external SSO redirect
- session expired response

This is recorded in `results.json` as `auth_state_loss_count` and examples.

Recent tuning goal:

- reduce false positives on authenticated business pages that contain words like `login`, `password`, or `portal` for legitimate reasons

Current logic now prefers stronger auth-loss evidence such as:

- real login-like UI
- auth redirect behavior
- 401 or 407 responses
- explicit session-expired markers

It avoids treating every page with a password field as a login page.

## Feature Extraction

Main feature extractor:

- [agent/agent/analysis/features.py](agent/agent/analysis/features.py)

`extract_features()` converts a raw response into structured signals such as:

- status code and redirect info
- content type and body class
- banner headers
- cookie observations
- runtime error strings
- file paths
- internal IPs
- phpinfo values
- config-style key/value pairs
- directory listing hints
- default resource hints
- auth-required, session-expired, and external-auth indicators

Important distinction:

- features are observations
- they are not findings yet

This separation lets the scanner keep broad visibility without reporting everything as a vulnerability.

## Rule-Based Classification

Main signal builder:

- [agent/agent/http/classifier.py](agent/agent/http/classifier.py)

Sub-classifiers:

- [agent/agent/http/http_policy_classifier.py](agent/agent/http/http_policy_classifier.py)
- [agent/agent/http/http_disclosure_classifier.py](agent/agent/http/http_disclosure_classifier.py)
- [agent/agent/http/http_resource_classifier.py](agent/agent/http/http_resource_classifier.py)
- [agent/agent/http/disclosure_enrichment.py](agent/agent/http/disclosure_enrichment.py)

These modules turn features into typed signals such as:

- `HTTP_ERROR_INFO_EXPOSURE`
- `HTTP_SYSTEM_INFO_EXPOSURE`
- `HTTP_CONFIG_FILE_EXPOSURE`
- `PHPINFO_EXPOSURE`
- `DIRECTORY_LISTING_ENABLED`
- `COOKIE_HTTPONLY_MISSING`
- `COOKIE_SECURE_MISSING`
- `DIRECT_COOKIE_SAMESITE_MISSING`

Signals are still intermediate. They become findings only after candidate generation, validation, and merge.

## Candidate Generation, Validation, And Verification

Main modules:

- [agent/agent/candidates.py](agent/agent/candidates.py)
- [agent/agent/analysis/verification_policy.py](agent/agent/analysis/verification_policy.py)
- [agent/agent/findings/store.py](agent/agent/findings/store.py)
- [agent/agent/findings/identity.py](agent/agent/findings/identity.py)

### Candidate Generation

`generate_candidates()` groups signals and creates finding-shaped records with:

- type
- title
- CWE and OWASP mapping
- severity
- evidence
- extracted information

### Validation

Validation removes or downgrades weak findings such as:

- keyword-only matches without a disclosed value
- broken binary text misread as a path
- generic `Fatal error` strings without meaningful details
- source markers like `<?php` without actual source/code disclosure

### Verification

Where practical, the scanner verifies behavior by replaying or comparing requests. Examples:

- authenticated vs anonymous response comparison
- resource exposure re-checks
- directory listing confirmation
- method handling confirmation

## Differential Disclosure

One of the most important improvements is anonymous vs authenticated replay for information disclosure.

Logic lives mainly in:

- [agent/agent/runtime/scan_results.py](agent/agent/runtime/scan_results.py)

Workflow:

1. Scan normally with authentication.
2. Re-request disclosure-related routes anonymously.
3. Extract structured disclosure values from both responses.
4. Compare `authenticated_values - anonymous_values`.
5. If authenticated-only values appear, mark the finding accordingly.

This allows findings such as:

- public disclosure
- authenticated-only disclosure
- authenticated-observed-only disclosure

### Visibility Fields

Relevant findings now carry:

- `visibility_scope`
  - `public_or_shared`
  - `authenticated_only`
  - `authenticated_observed_only`
  - `unknown`
- `exposure_context`
  - `public_or_shared`
  - `authenticated`
  - `differential_anonymous_vs_authenticated`

These fields are meant to prevent overclaiming. A finding seen only with a valid session should not be described the same way as a public exposure.

## False-Positive Control

The scanner is intentionally layered. Noise is reduced in several places instead of one giant filter.

### 1. Discovery pruning

Low-value routes are deprioritized or skipped.

Examples:

- static assets
- documentation-like pages
- destructive logout routes

### 2. Feature sanitization

Examples:

- binary garbage is rejected as a file path
- heavily masked values are not reported as leaked secrets
- trivial tokens such as `array (` are dropped

### 3. Classifier thresholds

Examples:

- generic login-like words are not enough for auth-loss on their own
- source markers are kept as supporting evidence rather than promoted directly
- weak DB errors are suppressed unless they contain real detail

### 4. Merge and dedupe

Stable identity keys merge repeated observations into one finding.

Examples:

- host-wide banner findings
- canonical URL normalization for synthetic `__nonexistent_*` probes
- repeated directory index pages

### 5. Differential replay

Anonymous replay helps answer whether data is really exposed publicly or only after authentication.

## CWE Mapping Strategy

The project no longer relies on broad `CWE-200` by default when a more precise mapping is available.

Current preferred mappings:

- `CWE-209`
  - error messages containing sensitive detail
- `CWE-497`
  - system, environment, path, phpinfo, internal address, runtime detail exposure
- `CWE-538`
  - externally accessible config files and config-like disclosures
- `CWE-548`
  - directory listing enabled
- `CWE-552`
  - exposed default or backup resources accessible over HTTP

`CWE-200` should be treated as a fallback umbrella mapping, not the first choice.

## Severity And Source Fields

Final output now uses a single top-level `severity`.

The report also exposes where classification came from:

- `classification_source`
  - usually `rule_based` or `rule_based_differential`
- `cwe_source`
  - usually `rule_based_mapping` or `rule_based_visibility_mapping`
- `severity_source`
  - usually `rule_based_policy`, `rule_based_differential_policy`, or `validation_policy`

This makes it clear whether the result came from:

- direct rule logic
- a differential comparison
- a later validation downgrade or upgrade

## Rule-Based Logic Vs LLM

The scanner is designed so that rule-based logic does the hard, reproducible work first.

### Rule-based responsibilities

- crawling
- probe generation
- response parsing
- feature extraction
- deterministic classification
- replay verification
- merge and dedupe
- final structured evidence assembly

### LLM responsibilities

When enabled, LLM use is intended for:

- candidate value triage
- report phrasing
- weak evidence cleanup
- future evidence-quality review

Important note:

- the current pipeline is fully capable of operating with LLM disabled
- CWE mapping and severity are currently rule-based unless explicit LLM review is added

## Additional HTTP-Detectable Disclosure CWE Ideas

Beyond the CWEs already implemented, good future candidates include:

- `CWE-201`
  - reflected sensitive data in response bodies
- `CWE-203`
  - observable discrepancies that reveal valid users, roles, or object existence
- `CWE-215`
  - debug information in responses
- `CWE-526`
  - environment variable exposure
- `CWE-537`
  - Java runtime error messages with sensitive details
- `CWE-540`
  - inclusion of sensitive information in source code
- `CWE-541`
  - inclusion of sensitive information in include files
- `CWE-598`
  - sensitive information in GET query strings

These should only be added when there is strong HTTP-observable evidence and a clear false-positive strategy.

## How To Read A Finding

A useful finding should answer these questions quickly:

- what was exposed?
- where was it observed?
- who could see it?
- how confident are we?
- which rule mapped it to this CWE and severity?

The top of the compact finding is intended to answer exactly that through:

- `type`
- `title`
- `visibility_scope`
- `exposure_context`
- `severity`
- `cwe`
- `classification_source`
- `cwe_source`
- `severity_source`

## Current Limitations

- Cookie attribute findings depend on actually observing `Set-Cookie`.
- Some auth-loss heuristics still need tuning on apps with many authenticated forms.
- Differential visibility is strongest today for anonymous vs authenticated, and can be extended later to user vs admin.
- LLM-based evidence review is not yet the default path, so weak evidence cleanup is still mostly heuristic.

## Practical Guidance For Testing

For realistic scans:

- provide at least one working authenticated account
- keep seed URLs focused on real app entry points
- test anonymous and authenticated visibility whenever possible
- prefer local reproducible apps such as DVWA and bWAPP before moving to harder enterprise targets

For role-aware disclosure analysis in the future:

- scan anonymously
- scan as normal user
- scan as admin
- compare which information appears only at each visibility level

That role-differential model is the most reliable way to distinguish:

- public exposure
- authenticated-only exposure
- overexposure to regular users
- admin-only operational detail
