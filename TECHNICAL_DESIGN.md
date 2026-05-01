# llmshieldr Technical Design

This document explains the technical design of `llmshieldr` in detail. It is
intended for maintainers, contributors, reviewers, and advanced users who want
to understand how the package works internally.

## Design Goals

`llmshieldr` is a safety layer for LLM workflows in R. Its core design goals
are:

- Keep the first user path simple: choose a built-in policy name and call a
  scanner.
- Keep the internals inspectable: policies are lists of explicit rules, not a
  hidden classifier.
- Support local-first safety workflows through deterministic rules, NLP checks,
  and Ollama review.
- Stay model-agnostic: any `ellmer` chat, object with `$chat()`, or plain R
  function can be used.
- Separate scanning from orchestration: prompt, context, and output scanners
  can be used independently or together through `secure_chat()`.
- Preserve auditability: scanner reports, final decisions, token estimates,
  and risk summaries are stored as R objects and can be written to logs.

## Package Layers

The package is organized into seven functional layers:

1. Rule and result constructors in `R/rules.R`
2. Built-in policy assembly in `R/policy.R`
3. Prompt scanning in `R/scan_prompt.R`
4. Context scanning in `R/scan_context.R`
5. Output scanning in `R/scan_output.R`
6. Chat orchestration and token accounting in `R/secure_chat.R`
7. Integration helpers for Ollama, trust boundaries, audits, examples, and
   explanations

The scanners are the main workhorses. Everything else either prepares a policy,
calls the scanners, explains the scanner findings, or persists the audit trail.

## Public API Map

Policy and rule functions:

- `policy()` returns a built-in `shieldr_policy`.
- `available_policies()` lists built-in policy names and behavior.
- `build_policy()` builds a custom policy from rule objects.
- `add_rule()` appends a custom rule to a policy.
- `remove_rule()` removes a rule by id.
- `list_rules()` prints and returns the rule inventory.
- `shieldr_rule()` creates one rule.
- `shieldr_policy()` creates the low-level policy object.

Scanner functions:

- `scan_prompt()` scans user prompt text.
- `preflight_check()` is a backward-compatible alias for `scan_prompt()`.
- `scan_context()` scans retrieved context rows.
- `scan_output()` scans model output text.

Workflow functions:

- `secure_chat()` runs prompt scan, optional context scan, chat call, output
  scan, rate guard update, and audit creation.
- `shield_ollama()` is a convenience path for local Ollama chat workflows.
- `ollama_reviewer()` creates an Ollama chat object used as a semantic reviewer.
- `trust_boundary()` wraps a chat object or function and validates exposed model
  or host metadata.
- `rate_guard()` creates or checks a stateful token/request guard.

Audit and presentation functions:

- `shieldr_report()` creates scanner reports.
- `shieldr_audit()` creates end-to-end audit objects.
- `shieldr_result()` creates the final result from `secure_chat()`.
- `write_audit_log()` writes JSONL, CSV, or RDS audit output.
- `explain_findings()` formats findings for console, Markdown, or HTML.
- `example_prompts()` returns a teaching and testing corpus.

## Object Model

The package uses simple S3 objects built on lists and environments.

### `shieldr_rule`

A rule is the smallest unit of detection. It is a list with class
`shieldr_rule` and these fields:

- `id`: stable rule identifier, such as `llm02.pii.email`.
- `pattern`: a Perl-compatible regular expression, or `NULL`.
- `fn`: an R predicate function, or `NULL`.
- `owasp`: optional OWASP LLM category such as `llm01`.
- `severity`: one of `low`, `medium`, `high`, or `critical`.
- `action`: one of `allow`, `redact`, or `block`.
- `description`: human-readable rule explanation.

Exactly one of `pattern` or `fn` must be supplied. This invariant is enforced
by `shieldr_rule()`. Regex rules can produce spans for redaction. Function
rules can express richer logic, but only redact spans when the function returns
span metadata.

### `shieldr_policy`

A policy is a list with class `shieldr_policy` and these fields:

- `name`: policy identifier stored in reports and audits.
- `rules`: list of `shieldr_rule` objects.
- `thresholds`: list with `redact_at` and `block_at`.
- `rate_guard`: optional `shieldr_rate_guard` environment.
- `trusted_sources`: optional character vector used by `scan_context()`.

Threshold validation happens in `.validate_thresholds()`. Both values must be
between `0` and `1`, and `redact_at` must be less than or equal to `block_at`.

### `shieldr_report`

A scanner report is a list with class `shieldr_report` and these fields:

- `action`: resolved action: `allow`, `redact`, or `block`.
- `text_clean`: normalized and possibly redacted text.
- `findings`: list of finding objects.
- `risk_score`: numeric score from `0` to `1`.
- `policy`: policy name.
- `checks`: check mode used.
- `timestamp`: UTC ISO8601 timestamp.
- `tokens`: optional token count when `show_tokens = TRUE`.

Reports are returned by `scan_prompt()`, `scan_context()`, and `scan_output()`.

### Finding Objects

Findings are plain lists. The standard fields are:

- `rule_id`
- `owasp`
- `severity`
- `action`
- `description`
- `match`
- `start`
- `end`
- `source`

Regex findings usually contain `match`, `start`, and `end`. Semantic reviewer
and synthetic findings often use `NA` span fields.

### `shieldr_audit`

An audit object stores the end-to-end workflow:

- `input_report`
- `output_report`
- `context_reports`
- `prompt_clean`
- `output_raw`
- `elapsed_ms`
- `token_estimate`
- `action`

`secure_chat()` creates this automatically. `write_audit_log()` serializes it.

### `shieldr_result`

The final result object returned by `secure_chat()` and `shield_ollama()` has:

- `output`: cleaned model output, or `NULL` when blocked.
- `audit`: a `shieldr_audit`.
- `risk_summary`: named numeric vector by OWASP category.
- `action`: final action.

## Built-In Policies

Built-in policies are assembled in `.built_in_policy()` and exposed through
`policy()`.

Supported policy names are:

- `enterprise_default`
- `baseline`
- `pharma_gxp`
- `finance_strict`
- `education_safe`
- `open_research`
- `comprehensive`
- `custom`

`baseline` is an alias for `enterprise_default`, but the returned object keeps
the requested name for backward-compatible reporting.

### Enterprise Rules

`enterprise_default` starts with:

- `rule_injection_basic()`
- `rule_injection_indirect()`
- `rule_nlp_intent()`
- `rule_pii_email()`
- `rule_pii_phone()`
- `rule_pii_ssn()`
- `rule_phi_condition()`
- `rule_secrets_api_key()`
- `rule_secrets_bearer()`
- `rule_secrets_aws()`
- `rule_secrets_password()`
- `.rule_secrets_connection_string()`
- `rule_system_prompt_leak()`
- `rule_agency_language()`

The goal is broad production coverage for injection, NLP intent, privacy,
secrets, system-prompt extraction, and excessive agency.

### Domain-Specific Additions

`pharma_gxp` adds:

- `.rule_pii_mrn()`
- `.rule_pii_usubjid()`
- `rule_diagnosis_claim()`
- `.rule_code_safety()`

It also lowers thresholds to `redact_at = 0.3` and `block_at = 0.6`.

`finance_strict` adds:

- `.rule_account_number()`
- `rule_financial_advice()`
- `.rule_investment_action()`

It also includes a token rate guard with `max_tokens = 100000`.

`education_safe` adds:

- `.rule_coppa_minor_pii()`
- `.rule_academic_integrity()`

`open_research` uses a smaller rule set focused on injection, NLP intent, and
secrets. It raises thresholds to `redact_at = 0.8` and `block_at = 0.95`.

`comprehensive` combines enterprise, pharma, finance, education, code-safety,
and rate-guard controls. It uses the stricter `pharma_gxp` threshold style.

`custom` has no rules and default thresholds.

## Check Modes

Scanners support four check modes:

- `rules`: run policy rules.
- `nlp`: run only NLP intent rules.
- `llm`: run only the supplied semantic reviewer.
- `both`: run policy rules and the supplied semantic reviewer.

This lets users choose between deterministic scanning, local NLP-only scanning,
local or remote LLM review, or a hybrid mode.

## Prompt Scanning Flow

`scan_prompt()` is implemented in `R/scan_prompt.R`.

The flow is:

1. Validate `text`, `policy`, `checks`, `redact`, `show_tokens`, and
   `reviewer`.
2. Normalize text with `.normalise_text()`.
3. Initialize an empty finding list.
4. If `checks` is `rules` or `both`, call `.run_rules()`.
5. If `checks` is `nlp`, call `.run_nlp()`.
6. If `checks` is `llm` or `both` and `reviewer` is supplied, call
   `.semantic_review()`.
7. Deduplicate findings with `.dedupe_findings()`.
8. Score findings with `.score_findings()`.
9. Resolve final scanner action with `.resolve_action()`.
10. Redact spans with `.apply_redaction()` when `redact = TRUE`.
11. Return a `shieldr_report()`.

### Text Normalization

`.normalise_text()` applies Unicode NFKC normalization through
`stringi::stri_trans_nfkc()` and collapses whitespace. This improves matching
against visually or structurally varied prompt text.

### Rule Execution

`.run_rules()` loops over every rule in the policy.

For regex rules:

- `gregexpr(..., perl = TRUE)` finds matches.
- Invalid regex rules are skipped with a warning.
- Each match becomes a finding with character start and end positions.

For function rules:

- The rule function receives the full normalized text.
- The return value is coerced by `.coerce_fn_findings()`.

Function rules can return:

- `NULL` or `FALSE`: no finding.
- `TRUE`: one default finding from the rule metadata.
- a data frame: one finding per row.
- one finding list.
- a list of finding lists.
- another value: converted to a match string.

### NLP-Only Execution

`.run_nlp()` extracts rules whose ids contain `.nlp.`. If the policy does not
include `llm01.nlp.intent`, it adds `rule_nlp_intent()` for the run. It then
calls `.run_rules()` with a temporary policy containing only NLP rules.

`rule_nlp_intent()` calls `.nlp_intent_findings()`, which looks for:

- override language plus instruction words
- reveal/extract language plus secret-related words
- harmful content terms plus action verbs
- unusually dense directive language

Tokenization happens in `.nlp_tokens()`:

- If `tokenizers` is installed, it uses `tokenizers::tokenize_words()`.
- Otherwise it lowercases and splits with base R.

Stemming happens in `.nlp_stems()`:

- If `SnowballC` is installed, it uses `SnowballC::wordStem()`.
- Otherwise it applies a simple suffix-stripping fallback.

This design gives a useful local signal without making `tokenizers` or
`SnowballC` required dependencies.

### Semantic Reviewer Execution

`.semantic_review()` builds a reviewer prompt and expects JSON findings.

The reviewer can be:

- a function that accepts one prompt string
- an object with a `$chat()` method

The reviewer is asked to return only JSON: an array of objects with:

- `rule_id`
- `owasp`
- `severity`
- `description`

Malformed JSON is treated as a soft failure. A warning is emitted and existing
rule findings are preserved.

## Output Scanning Flow

`scan_output()` is implemented in `R/scan_output.R`.

Output scanning starts with the supplied policy, then calls `.output_policy()`.
That helper adds output-specific intrinsic rules when the policy does not
already contain them:

- `.rule_code_safety()`
- `rule_agency_language()`
- `.rule_output_system_markers()`
- `rule_diagnosis_claim()`
- `.rule_misinformation_marker()`

The output scanner then:

1. Validates inputs.
2. Normalizes with NFKC.
3. Extracts fenced code blocks.
4. Scans code blocks with `llm05.*` rules.
5. Offsets code-block findings back to their original positions.
6. Scans the full output policy.
7. Optionally runs NLP-only or semantic-review checks, depending on `checks`.
8. Deduplicates, scores, resolves action, redacts, and returns a report.

The code-block pass exists because unsafe commands often appear inside fenced
snippets, and those snippets deserve focused scanning before general output
rules run.

## Context Scanning Flow

`scan_context()` is implemented in `R/scan_context.R`.

Context scanning treats each retrieved row as its own trust boundary.

The flow is:

1. Validate that `data` is a data frame.
2. Convert `policy` names to policy objects with `.as_policy()`.
3. Validate check mode, reviewer, anomaly threshold, and token option.
4. Infer or resolve the text column.
5. Resolve optional `source_col`.
6. Convert text column to character and replace `NA` with empty strings.
7. Compute robust Z-scores for character length.
8. Compute instruction density and robust Z-scores for density.
9. For each row, create synthetic findings for anomalies and untrusted source.
10. Call `scan_prompt()` on the row text.
11. Merge synthetic and scan findings.
12. Re-score and re-resolve action.
13. Return one `shieldr_report` per row.

### Text Column Inference

If `text_col` is omitted, `.infer_scan_context_text_col()` checks for common
column names:

- `text`
- `context`
- `content`
- `chunk`
- `document`

If none exists, it uses the first character column. If there is no character
column, it errors.

### Anomaly Detection

Context anomaly detection is intentionally simple and transparent.

Length anomaly:

- Compute `nchar(text)` for every row.
- Convert to robust Z-score using median and MAD.
- Flag rows above `anomaly_threshold`.

Instruction density:

- Count words matching `ignore`, `forget`, `override`, `instead`, or
  `disregard`.
- Divide by token count.
- Express as hits per 100 tokens.
- Convert to robust Z-score.
- Flag rows above `anomaly_threshold`.

Synthetic anomaly findings use OWASP `llm08`.

### Trusted Sources

If a policy has `trusted_sources` and `source_col` is supplied, rows whose
source value is missing or outside the allowlist receive an
`llm08.untrusted_source` finding.

This does not automatically block the row. It contributes risk and lets the
normal action resolver decide.

## Action Resolution

`.resolve_action()` maps findings and score to `allow`, `redact`, or `block`.

The order is conservative:

1. Return `block` if any finding has severity `critical`.
2. Return `block` if any finding action is `block`.
3. Return `block` if `risk_score >= policy$thresholds$block_at`.
4. Return `redact` if any finding action is `redact`.
5. Return `redact` if `risk_score >= policy$thresholds$redact_at`.
6. Otherwise return `allow`.

This means a single critical finding can block even if thresholds are lenient.
It also means redaction can occur from an explicit rule action even when the
numeric score is below `redact_at`.

## Scoring Model

`.severity_score()` maps severity to numeric contribution:

- `low`: `0.1`
- `medium`: `0.3`
- `high`: `0.6`
- `critical`: `1.0`

`.score_findings()` sums all finding scores and caps the report at `1.0`.

This score is not a probability. It is a deterministic severity index used for
policy action resolution and summaries.

## Redaction

`.apply_redaction()` replaces matched spans with `[REDACTED]`.

The algorithm:

1. Extract numeric `start` and `end` spans from findings.
2. Drop findings without valid spans.
3. Sort spans by start and end position.
4. Merge overlapping or adjacent spans.
5. Replace merged spans from left to right while tracking offset changes.

Merging is important because overlapping findings are common. For example, a
secret-bearing connection string can include a password that also matches a
password rule.

## Secure Chat Orchestration

`secure_chat()` is implemented in `R/secure_chat.R`.

The workflow is:

1. Validate prompt and chat object.
2. Convert policy name to policy object.
3. Validate check mode and reviewer.
4. Start elapsed-time timer.
5. Run `scan_prompt()`.
6. If prompt action is `block`, return immediately without calling chat.
7. If context is supplied, run `scan_context()`.
8. Append only non-blocked context rows to the cleaned prompt.
9. Check the rate guard, if present.
10. Snapshot `ellmer::token_usage()` when token display is enabled.
11. Call the chat object or function.
12. Snapshot `ellmer::token_usage()` again.
13. Run `scan_output()` on raw model output.
14. Combine prompt and output actions.
15. Estimate token usage.
16. Update the rate guard, if present.
17. Create `shieldr_audit()`.
18. Return `shieldr_result()`.

### Chat Argument Handling

`secure_chat()` accepts `chat` as the public argument. It also accepts
`provider =` through `...` as a backward-compatible alias.

`.validate_chat()` accepts:

- a plain function
- an object with a `$chat()` method

`.call_chat()` calls functions directly or delegates to `$chat()`.

### Context Assembly

When context is supplied, `secure_chat()` scans every row. Only rows whose
context report action is not `block` are appended to the final prompt.

The final prompt format is:

```text
<cleaned prompt>

Context:

<safe context row 1>

<safe context row 2>
```

Blocked context rows are omitted. They still appear in the audit through
`context_reports`.

### Final Action Combination

`.combine_actions()` applies conservative precedence:

1. `block`
2. `redact`
3. `allow`

If either prompt or output blocks, the final result blocks.

## Token Counting

Token counts are optional and enabled with `show_tokens = TRUE`.

For scanner reports, `.count_tokens()` is called on the original text. It tries
to find an available token-counting function in the `ellmer` namespace. If that
does not work, it falls back to:

```r
ceiling(nchar(text, type = "chars") / 4)
```

For `secure_chat()`, `.ellmer_usage_snapshot()` captures
`ellmer::token_usage()` before and after the chat call when available.
`.ellmer_usage_delta()` computes the delta over token columns such as `input`,
`output`, and `cached_input`. If a positive delta is not available,
`secure_chat()` falls back to `.count_tokens(final_prompt, raw_output)`.

The token estimate is intended for guardrails and trend monitoring. It is not a
billing reconciliation mechanism.

## Rate Guard Design

`rate_guard()` has two modes.

Creation mode:

```r
guard <- rate_guard(max_tokens = 100000, max_requests = 500)
```

This returns a mutable environment with class `shieldr_rate_guard`.

Checking mode:

```r
rate_guard(guard)
```

This validates current usage against configured limits.

The environment stores:

- `.tokens_used`
- `.requests_made`
- `.window_start`
- `.max_tokens`
- `.max_requests`
- `.window_seconds`

Methods on the environment:

- `$usage()` resets the window if expired and returns counters and limits.
- `$update(tokens)` resets if expired, increments token and request counters,
  and returns usage invisibly.

Limits set to `NULL` are disabled for that dimension.

## Ollama Integration

`shield_ollama()` and `ollama_reviewer()` live in `R/shield_ollama.R`.

`shield_ollama()`:

- checks that `ellmer` is installed
- creates an assistant chat with `ellmer::chat_ollama(model = model)`
- creates a separate reviewer chat only when `checks` is `llm` or `both`
- delegates to `secure_chat()`

The separate reviewer chat prevents safety-review prompts from mixing into the
assistant conversation state.

`ollama_reviewer()`:

- checks that `ellmer` is installed
- validates `model`
- returns `ellmer::chat_ollama(model = model, ...)`

It is a convenience helper. Users can pass any reviewer function or chat object
instead.

## Trust Boundary Design

`trust_boundary()` wraps a chat object or function and validates identity before
calls cross a model-service boundary.

It can check:

- `allowed_models`
- `allowed_hosts`
- `require_hash` for local Ollama model manifests

Plain functions pass through model and host checks because functions have no
standard metadata. Chat objects with `$chat()` may expose model and host data
through attributes or common ellmer-style internals.

`require_hash` uses:

```text
ollama show --modelfile <model>
```

The returned manifest text is hashed with SHA-256 through `digest::digest()`.

This is not a network firewall. It is an application-level assertion that the
object being called is the intended object.

## Audit Logging

`write_audit_log()` supports three formats:

- `jsonl`
- `csv`
- `rds`

JSONL:

- appends one JSON object per line
- preserves nested audit structure better than CSV
- uses `.strip_classes()` so S3 classes and environments are serializable

CSV:

- flattens findings into one row per finding
- includes stage, report index, action, risk score, rule id, OWASP category,
  severity, description, and source
- is convenient for spreadsheets and simple dashboards

RDS:

- saves the exact R object
- overwrites the target path, with a warning if the file exists

Audit logs may contain sensitive text. The caller is responsible for storing
them in an appropriate location.

## Risk Summary

`.risk_summary()` collects findings from input, output, and context reports.

It:

1. Recursively collects `shieldr_report` objects.
2. Extracts findings.
3. Groups severity scores by OWASP category.
4. Sums each category.
5. Caps each category at `1.0`.

The output is a named numeric vector. It is useful for dashboards because it
shows which OWASP category dominated a run.

## Dependency Strategy

Required imports:

- `cli`: errors, warnings, console presentation.
- `digest`: SHA-256 hashing for trust-boundary model checks.
- `httr2`: reserved for HTTP-oriented integrations.
- `jsonlite`: semantic reviewer JSON parsing and audit JSON serialization.
- `rlang`: dependency checks.
- `stringi`: Unicode normalization.

Suggested packages:

- `ellmer`: Ollama chat objects and token usage.
- `tokenizers`: optional NLP tokenization.
- `SnowballC`: optional stemming.
- `testthat`: tests.
- `knitr` and `rmarkdown`: vignettes.
- `withr` and `dplyr`: development/testing support.

The package intentionally keeps local NLP and Ollama features optional. Users
who only want regex rules and scanner reports do not need those packages.

## Error Handling

Validation helpers centralize common checks:

- `.check_string()`
- `.check_choice()`
- `.check_number_between()`
- `.check_rule_list()`
- `.check_policy()`
- `.check_report()`
- `.check_report_list()`
- `.check_rate_guard()`

Errors use `cli::cli_abort()` so arguments and values are displayed clearly.

Soft failures are used where guardrails should degrade gracefully:

- invalid regex rule: warn and skip that rule
- semantic reviewer error: warn and continue with existing findings
- malformed reviewer JSON: warn and ignore semantic findings
- unavailable token counter: fall back to character heuristic

## Extension Points

Users can extend the package in several ways.

Add regex rules:

```r
guardrails <- add_rule(
  policy(),
  id = "llm02.ticket_id",
  pattern = "\\bTICKET-[0-9]{6}\\b",
  owasp = "llm02",
  severity = "medium",
  action = "redact",
  description = "Internal support ticket identifier."
)
```

Add function rules:

```r
student_address <- function(text) {
  grepl("\\bstudent\\b", text, ignore.case = TRUE) &&
    grepl("\\bhome address\\b", text, ignore.case = TRUE)
}

guardrails <- add_rule(
  policy(),
  id = "llm02.student.address",
  fn = student_address,
  owasp = "llm02",
  severity = "high",
  action = "redact",
  description = "Student home address reference."
)
```

Use any chat function:

```r
chat <- function(prompt) {
  paste("MODEL RESPONSE:", prompt)
}

secure_chat("hello", chat = chat)
```

Use any reviewer function:

```r
reviewer <- function(prompt) {
  "[]"
}

scan_prompt("hello", reviewer = reviewer, checks = "llm")
```

## Testing Strategy

The test suite is organized around behavior:

- policy construction and built-in policies
- prompt scanning
- output scanning
- context scanning
- secure chat orchestration
- rate guard behavior
- audit writing
- trust boundary validation

Tests use mock functions for chat and reviewer behavior so package behavior can
be verified without external LLM calls.

## Known Boundaries

`llmshieldr` is a guardrail layer, not a guarantee of safety.

Important boundaries:

- Regex and NLP rules are transparent but not exhaustive.
- Semantic review quality depends on the reviewer model or function.
- Token counts are estimates unless `ellmer` usage records are available.
- Trust boundaries validate application-level metadata; they do not replace
  network controls.
- Audit logs can contain sensitive text and must be protected by the caller.
- Built-in policies are useful defaults, not legal compliance certifications.

## File-Level Design Reference

- `R/rules.R`: S3 constructors, built-in rule helpers, scoring helpers,
  validation helpers, NLP token/stem helpers.
- `R/policy.R`: built-in policy assembly, policy inventory, add/remove/list
  rule helpers.
- `R/scan_prompt.R`: prompt scanner, rule runner, NLP runner, semantic review,
  redaction, scoring, deduplication.
- `R/scan_context.R`: data-frame context scanner, source trust, anomaly
  findings.
- `R/scan_output.R`: model output scanner and output-specific policy expansion.
- `R/secure_chat.R`: end-to-end orchestration, token accounting, action
  combination, risk summary.
- `R/shield_ollama.R`: local Ollama assistant/reviewer helpers.
- `R/trust_boundary.R`: model/host/hash validation wrapper.
- `R/rate_guard.R`: stateful request/token guard.
- `R/audit.R`: audit serialization and finding flattening.
- `R/explain.R`: finding explanation formatting.
- `R/example_data.R`: teaching and testing examples.
- `app.R`: standalone Shiny demo app, excluded from package builds.

## End-to-End Mental Model

The shortest mental model is:

```text
policy() creates rules and thresholds
scan_prompt() turns prompt text into a report
scan_context() turns retrieved rows into reports
secure_chat() calls the model only if input is safe enough
scan_output() turns model output into a report
shieldr_result() returns safe output plus a full audit
write_audit_log() persists the audit
```

The package is deliberately simple: every decision comes from explicit
findings, severity scores, thresholds, and conservative action precedence.
