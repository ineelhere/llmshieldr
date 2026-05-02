# llmshieldr Technical and General Documentation

This document is the package-level handbook for `llmshieldr`. It explains what
the package does, how users should think about it, how each feature works, and
how the implementation is organized internally.

The audience is deliberately broad:

- Users who want a practical mental model before adding guardrails to an LLM
  workflow.
- Maintainers who need to understand the package architecture.
- Reviewers who want to inspect how safety decisions are produced.
- Contributors who want to add rules, policies, scanners, examples, or
  integrations without breaking the design.

`llmshieldr` is a safety layer for LLM workflows in R. It is not a model
provider, a classifier, a moderation service, or a compliance certification.
Its core value is transparent guardrail orchestration: prompts, retrieved
context, and model outputs are scanned with explicit policies, findings are
scored deterministically, and the final decision is returned as an auditable R
object.

## Quick Mental Model

The shortest model is:

```text
policy() creates a set of rules and thresholds
scan_prompt() checks user input before it reaches a model
scan_context() checks retrieved rows before they are added to a prompt
secure_chat() orchestrates scanning, chat execution, output scanning, and audit
scan_output() checks model text before it is displayed, stored, or used
write_audit_log() persists the end-to-end evidence trail
```

The package keeps the safety path inspectable. Every scanner result is based on
explicit findings. Every finding has a rule id, severity, action, optional OWASP
LLM category, and optional character span. The final action is one of
`allow`, `redact`, or `block`.

## Design Goals

`llmshieldr` is designed around these principles:

- Keep the first user path simple: choose a built-in policy name and call a
  scanner.
- Keep the internals inspectable: policies are lists of explicit rules, not a
  hidden classifier.
- Support local-first safety workflows through deterministic rules, NLP checks,
  and optional Ollama review.
- Stay model-agnostic: any `ellmer` chat, object with `$chat()`, or plain R
  function can be used.
- Separate scanning from orchestration: prompt, context, and output scanners can
  be used independently or together through `secure_chat()`.
- Preserve auditability: scanner reports, final decisions, token estimates, and
  risk summaries are stored as R objects and can be written to logs.
- Degrade gracefully where possible: bad reviewer JSON, missing token counters,
  and invalid optional integrations should not destroy deterministic scanner
  output.
- Keep domain controls extensible: built-in policies are useful defaults, but
  custom policy objects and custom rules are first-class.

## What The Package Protects

The built-in controls are organized around common LLM application risks,
including the OWASP GenAI / LLM Top 10 taxonomy.

Typical risks addressed by `llmshieldr` include:

- Prompt injection and jailbreak language.
- Indirect instructions hidden inside retrieved context.
- Personally identifiable information, protected health information, and
  secrets.
- Unsafe code or command suggestions in model output.
- Excessive agency claims such as pretending to send, delete, trade, or execute
  actions.
- Attempts to extract system or developer instructions.
- RAG-specific untrusted-source and context-anomaly signals.
- Unsupported diagnosis, treatment, financial, or misinformation-style claims.
- Resource exhaustion through token and request guards.
- Model identity and host checks for application-level trust boundaries.

These controls are intentionally conservative and transparent. They are
designed to catch common failure modes, not to guarantee that every unsafe input
or output will be detected.

## Package Layers

The package is organized into seven functional layers:

1. Rule, report, audit, and result constructors in `R/rules.R`
2. Built-in policy assembly and policy mutation helpers in `R/policy.R`
3. Prompt scanning in `R/scan_prompt.R`
4. Context scanning in `R/scan_context.R`
5. Output scanning in `R/scan_output.R`
6. Chat orchestration and token accounting in `R/secure_chat.R`
7. Integration helpers for Ollama, trust boundaries, audits, examples, and
   explanations

The scanners are the main workhorses. Everything else either prepares a policy,
calls the scanners, explains scanner findings, validates a chat boundary, or
persists the audit trail.

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
- `reviewer_prompt()` returns the default semantic reviewer prompt.

Audit and presentation functions:

- `shieldr_report()` creates scanner reports.
- `shieldr_audit()` creates end-to-end audit objects.
- `shieldr_result()` creates the final result from `secure_chat()`.
- `write_audit_log()` writes JSONL, CSV, or RDS audit output.
- `explain_findings()` formats findings for console, Markdown, or HTML.
- `example_prompts()` returns a teaching and testing corpus.

## End-to-End User Workflow

A typical user workflow looks like this:

1. Select a policy:

   ```r
   guardrails <- policy("enterprise_default")
   ```

2. Preflight the prompt:

   ```r
   input_report <- scan_prompt("Summarize this for jane@example.com.", guardrails)
   input_report$action
   input_report$text_clean
   ```

3. Optionally scan retrieved context:

   ```r
   context_reports <- scan_context(context_df, policy = guardrails)
   ```

4. Run the guarded chat workflow:

   ```r
   result <- secure_chat(
     prompt = "Summarize the support thread.",
     chat = chat,
     policy = guardrails,
     context = context_df,
     show_tokens = TRUE
   )
   ```

5. Inspect the result:

   ```r
   result$action
   result$output
   result$risk_summary
   ```

6. Persist the audit trail:

   ```r
   write_audit_log(result$audit, "audit.jsonl")
   ```

The user can also call `scan_prompt()`, `scan_context()`, and `scan_output()`
independently when they do not need orchestration.

## Core Object Model

The package uses simple S3 objects built on lists and environments. This keeps
the objects easy to print, test, serialize, and inspect.

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
by `shieldr_rule()`.

Rule ids should follow the `llmXX.category.name` convention where possible.
Non-conforming ids still work, but `shieldr_rule()` warns because OWASP risk
summaries are clearest when rule ids carry a category prefix.

Regex rules are best for direct matching and redaction because they produce
character spans. Function rules are best when a finding depends on logic that is
awkward to express as a single pattern. Function rules can still redact text if
they return finding objects with `start` and `end` span metadata.

### `shieldr_policy`

A policy is a list with class `shieldr_policy` and these fields:

- `name`: policy identifier stored in reports and audits.
- `rules`: list of `shieldr_rule` objects.
- `thresholds`: list with `redact_at` and `block_at`.
- `rate_guard`: optional `shieldr_rate_guard` environment.
- `trusted_sources`: optional character vector used by `scan_context()`.

Threshold validation happens in `.validate_thresholds()`. Both threshold values
must be between `0` and `1`, and `redact_at` must be less than or equal to
`block_at`.

Policies are not mutated by scanners. Scanners read the policy and return new
report objects. The main exception in the package is `rate_guard`, which is
intentionally mutable because rate limiting is session state.

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
The print method shows the action, risk score, finding count, and optional token
count.

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

Regex findings usually contain `match`, `start`, and `end`. NLP, semantic
reviewer, and synthetic findings often use `NA` span fields because they may
identify risk without knowing an exact redaction span.

The `source` field indicates where the finding came from, typically `rules`,
`nlp`, or `llm`.

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

This object is intended to be the application-facing return value. The user can
show `output`, branch on `action`, and store `audit`.

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

### `enterprise_default`

`enterprise_default` is the broad production baseline. It starts with:

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

The goal is broad coverage for injection, NLP intent, privacy, secrets,
system-prompt extraction, and excessive agency.

### `pharma_gxp`

`pharma_gxp` adds:

- `.rule_pii_mrn()`
- `.rule_pii_usubjid()`
- `rule_diagnosis_claim()`
- `.rule_code_safety()`

It lowers thresholds to:

```r
list(redact_at = 0.3, block_at = 0.6)
```

This policy is intended for clinical, pharmaceutical, and regulated workflows
where PHI, clinical identifiers, diagnosis claims, and unsafe code deserve
stricter treatment. It is not a legal compliance certification.

### `finance_strict`

`finance_strict` adds:

- `.rule_account_number()`
- `rule_financial_advice()`
- `.rule_investment_action()`

It also includes a token rate guard:

```r
rate_guard(max_tokens = 100000)
```

This policy focuses on account identifiers, investment advice language,
autonomous trading claims, and resource limits.

### `education_safe`

`education_safe` adds:

- `.rule_coppa_minor_pii()`
- `.rule_academic_integrity()`

This policy is intended for classroom, tutoring, student support, and
education-adjacent workflows where minor-related PII and academic-integrity
bypass requests are important risks.

### `open_research`

`open_research` uses a smaller rule set focused on:

- prompt injection
- NLP intent
- secrets

It raises thresholds to:

```r
list(redact_at = 0.8, block_at = 0.95)
```

This policy is intentionally more permissive for exploratory and research
settings while still catching high-risk injection and secret exposure patterns.

### `comprehensive`

`comprehensive` combines enterprise, pharma, finance, education, code-safety,
and rate-guard controls. It uses moderate threshold behavior:

```r
list(redact_at = 0.4, block_at = 0.7)
```

It is the maximum-coverage built-in profile. For pharma-tier strictness, users
can supply:

```r
overrides = list(thresholds = list(redact_at = 0.3, block_at = 0.6))
```

### `custom`

`custom` has no rules and default thresholds:

```r
list(redact_at = 0.4, block_at = 0.75)
```

It is useful when applications want to assemble their entire safety policy from
custom rules.

### Policy Overrides

`policy()` accepts an `overrides` list. Supported entries are:

- `rules`: additional `shieldr_rule` objects appended to the built-in rules.
- `thresholds`: values merged over the built-in thresholds.
- `rate_guard`: replacement `shieldr_rate_guard`.
- `trusted_sources`: character vector used by `scan_context()`.

Example:

```r
guardrails <- policy(
  "enterprise_default",
  overrides = list(
    thresholds = list(redact_at = 0.35),
    trusted_sources = c("kb-prod", "policy-handbook")
  )
)
```

## Rule Bank

The rule bank lives in `R/rules.R`. Exported rule helpers include:

- `rule_injection_basic()`: direct prompt-injection and jailbreak language.
- `rule_injection_indirect()`: hidden instructions and role confusion inside
  supplied text.
- `rule_nlp_intent()`: token and stem based intent detection.
- `rule_pii_email()`: email addresses.
- `rule_pii_phone()`: US-style phone numbers.
- `rule_pii_ssn()`: US Social Security number pattern.
- `rule_phi_condition()`: health condition references near patient language.
- `rule_secrets_api_key()`: API key and API secret literals.
- `rule_secrets_bearer()`: bearer tokens.
- `rule_secrets_aws()`: AWS access key identifiers.
- `rule_secrets_password()`: password and passcode literals.
- `rule_system_prompt_leak()`: requests to reveal system or developer
  instructions.
- `rule_agency_language()`: model claims or proposes autonomous actions.
- `rule_diagnosis_claim()`: high-confidence diagnosis or treatment claims.
- `rule_financial_advice()`: investment advice or guaranteed-return language.

Internal rule helpers add policy-specific controls such as connection strings,
MRNs, clinical subject IDs, unsafe code, account numbers, investment actions,
minor PII, academic-integrity bypasses, system markers in output, and
misinformation markers.

## Check Modes

Scanners support four check modes:

- `rules`: run policy rules.
- `nlp`: run only NLP intent rules.
- `llm`: run only the supplied semantic reviewer.
- `both`: run policy rules and the supplied semantic reviewer.

Important behavior:

- Built-in policies include `rule_nlp_intent()` in their rule list, so
  `checks = "rules"` can still run the NLP intent rule when the selected policy
  contains it.
- `checks = "nlp"` filters the policy to rules whose ids contain `.nlp.`. If
  `llm01.nlp.intent` is missing, the scanner adds it for that run.
- `checks = "llm"` does nothing unless a reviewer function or reviewer chat
  object is supplied.
- `checks = "both"` combines deterministic policy rules with semantic reviewer
  findings.

This lets users choose deterministic scanning, local NLP-only scanning, LLM
review, or a hybrid mode.

## Scoring Model

`.severity_score()` maps severity to numeric contribution:

| Severity | Contribution |
| --- | ---: |
| `low` | 0.1 |
| `medium` | 0.3 |
| `high` | 0.6 |
| `critical` | 1.0 |

`.score_findings()` sums all normal finding scores and caps the report at
`1.0`. Findings are deduplicated before scoring in the scanner workflow.

Synthetic context findings are handled separately. Findings with
`synthetic = TRUE` contribute to a synthetic subtotal, and that subtotal is
capped at `0.3` per context row before it is added to normal rule-finding
scores.

This score is not a probability. It is a deterministic severity index used for
policy action resolution and summaries.

Example:

```text
email finding      medium   0.3
secret finding     high     0.6

risk_score = min(0.3 + 0.6, 1.0) = 0.9

synthetic context findings:
    high length anomaly          0.6
    medium untrusted source      0.3

synthetic subtotal = min(0.6 + 0.3, 0.3) = 0.3
```

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

Findings without spans still affect scoring and action resolution. They simply
do not alter `text_clean`.

## Feature Workflow: `policy()`

`policy()` is the easiest entry point for users.

Workflow:

1. Receive a policy name and optional overrides.
2. Treat `baseline` as an alias for `enterprise_default`.
3. Validate that the requested policy name is supported.
4. Assemble the built-in rule list for that policy.
5. Select policy-specific thresholds.
6. Create a rate guard for `finance_strict` or `comprehensive`.
7. Merge override rules, thresholds, rate guard, and trusted sources.
8. Return a validated `shieldr_policy`.

Maintainer notes:

- Built-in policy assembly is centralized in `.built_in_policy()`.
- Policy names and descriptions for discovery live in `.built_in_policy_info()`.
- `available_policies()` constructs each built-in policy to report rule counts,
  thresholds, and rate-guard availability.

## Feature Workflow: `build_policy()`

`build_policy()` constructs a custom policy from rule objects.

Workflow:

1. Validate `name`.
2. Validate that every element of `rules` inherits from `shieldr_rule`.
3. Merge supplied threshold values over the defaults:

   ```r
   list(redact_at = 0.4, block_at = 0.75)
   ```

4. Call `shieldr_policy()` to validate thresholds and rate guard.
5. Return the `shieldr_policy`.

Use this when an application wants a policy that does not start from a built-in
profile.

## Feature Workflow: `add_rule()`

`add_rule()` appends a custom rule to an existing policy.

Workflow:

1. Convert a policy name to a `shieldr_policy` with `.as_policy()`.
2. Validate the new rule id.
3. Check that the id is not already present in the policy.
4. Construct a `shieldr_rule()` from the supplied pattern or function.
5. Append the rule to `policy$rules`.
6. Return the modified policy invisibly.

Regex example:

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

Function example:

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

## Feature Workflow: `remove_rule()`

`remove_rule()` removes a rule by id.

Workflow:

1. Convert a policy name to a `shieldr_policy`.
2. Validate `id`.
3. Compute rule ids in the current policy.
4. Drop rules whose id matches the supplied id.
5. Warn if no matching rule existed.
6. Return the modified policy invisibly.

This helper is useful for starting from a built-in policy and removing a rule
that is too strict for a specific workflow.

## Feature Workflow: `list_rules()`

`list_rules()` prints and returns a compact rule inventory.

Workflow:

1. Convert a policy name to a `shieldr_policy`.
2. Build a data frame with:
   - `id`
   - `owasp`
   - `severity`
   - `action`
   - `has_pattern`
   - `has_fn`
3. Print the policy name and rule count.
4. Print the inventory table when it has rows.
5. Return the data frame.

Use this for audits, demos, tests, and policy reviews.

## Feature Workflow: `scan_prompt()`

`scan_prompt()` is implemented in `R/scan_prompt.R`. It is usually the first
guardrail in a workflow.

High-level purpose:

- Validate user prompt text before it reaches a model.
- Normalize the text so patterns match visually or structurally varied input.
- Run deterministic, NLP, and optional semantic-review checks.
- Return a `shieldr_report`.

Detailed workflow:

1. Validate `text`, `policy`, `checks`, `redact`, `show_tokens`, and
   `reviewer`.
2. Convert policy names to policy objects with `.as_policy()`.
3. Normalize text with `.normalise_text()`.
4. Initialize an empty finding list.
5. If `checks` is `rules` or `both`, call `.run_rules()`.
6. If `checks` is `nlp`, call `.run_nlp()`.
7. If `checks` is `llm` or `both` and `reviewer` is supplied, call
   `.semantic_review()`.
8. Deduplicate findings with `.dedupe_findings()`.
9. Score findings with `.score_findings()`.
10. Resolve final scanner action with `.resolve_action()`.
11. Redact spans with `.apply_redaction()` when `redact = TRUE`.
12. Count tokens when `show_tokens = TRUE`.
13. Return a `shieldr_report()`.

### Prompt Text Normalization

`.normalise_text()` applies several normalization passes in order:

1. Unicode NFKC normalization through `stringi::stri_trans_nfkc()`.
2. Leading and trailing whitespace trimming plus whitespace collapse.
3. A small hardcoded ASCII-confusable map for common accented Latin characters
   and lookalikes such as Cyrillic `і`.
4. Delimiter-split word collapse for evasions such as `i.g.n.o.r.e`,
   `i g n o r e`, and `i-g-n-o-r-e`.

The whitespace pass uses:

```r
gsub("\\s+", " ", trimws(text), perl = TRUE)
```

This improves matching against prompt text that uses unusual Unicode forms,
lookalike characters, or single-character delimiter splitting.

### Rule Execution

`.run_rules()` loops over every rule in the policy.

For regex rules:

- `gregexpr(..., perl = TRUE)` finds matches.
- Invalid regex rules are skipped with a warning.
- Each match becomes a finding with character start and end positions.
- The source is recorded as `rules`.

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

`rule_nlp_intent()` calls `.nlp_intent_findings()`, which builds seed groups
for override, reveal/extract/leak, and harmful-content terms. Each group is
expanded with `.nlp_stems()` at runtime. It then looks for:

- override language plus instruction words
- reveal, extract, or leak language plus secret-related words
- harmful content terms plus action verbs
- unusually dense directive language

The override seed group includes `ignore`, `forget`, `override`, `instead`,
`disregard`, `bypass`, `skip`, `suppress`, `cancel`, and `nullify`.

Tokenization happens in `.nlp_tokens()`:

- If `tokenizers` is installed, it uses `tokenizers::tokenize_words()`.
- Otherwise it lowercases and splits with base R.

Stemming happens in `.nlp_stems()`:

- If `SnowballC` is installed, it uses `SnowballC::wordStem()`.
- Otherwise it applies a simple suffix-stripping fallback.

This design gives a useful local signal without making `tokenizers` or
`SnowballC` required dependencies.

### Semantic Reviewer Execution

`.semantic_review()` builds a reviewer prompt from `.shieldr_reviewer_prompt`
and expects JSON findings. The public `reviewer_prompt()` helper returns this
default prompt for inspection.

The reviewer can be:

- a function that accepts one prompt string
- an object with a `$chat()` method

The reviewer is asked to return JSON: an array of objects with:

- `rule_id`
- `owasp`
- `severity`
- `description`

The parser also accepts a top-level object with a `findings` field. Malformed
JSON is treated as a soft failure. A warning is emitted and existing rule
findings are preserved.

Semantic findings do not carry redaction spans. They use `source = "llm"`.
Critical semantic findings resolve to `action = "block"`; other severities
resolve to `action = "redact"`.

Users who need a custom reviewer prompt should wrap their reviewer function or
chat object and prepend custom context before delegating to the model.

## Feature Workflow: `preflight_check()`

`preflight_check()` is a backward-compatible alias for `scan_prompt()`.

Workflow:

1. Accept the same main arguments as `scan_prompt()`.
2. Forward all arguments to `scan_prompt()`.
3. Return the resulting `shieldr_report`.

New code should generally call `scan_prompt()` directly, but keeping
`preflight_check()` preserves older user workflows.

## Feature Workflow: `scan_context()`

`scan_context()` is implemented in `R/scan_context.R`. It treats each retrieved
row as its own trust boundary.

High-level purpose:

- Detect prompt-injection or secret content inside retrieved context.
- Identify anomalous context rows.
- Flag untrusted sources when a trusted-source allowlist is configured.
- Return one `shieldr_report` per row.

Detailed workflow:

1. Validate that `data` is a data frame.
2. Convert policy names to policy objects with `.as_policy()`.
3. Validate check mode, reviewer, anomaly threshold, and token option.
4. Infer or resolve the text column.
5. Resolve optional `source_col`.
6. Convert text column to character and replace `NA` with empty strings.
7. Compute robust Z-scores for character length.
8. Compute instruction density and robust Z-scores for density.
9. For each row, create synthetic findings for anomalies and untrusted source.
10. Call `scan_prompt()` on the row text.
11. Merge synthetic and scan findings.
12. Deduplicate, score, and resolve action.
13. Redact with combined findings.
14. Return one `shieldr_report` per row.

### Context Text Column Inference

If `text_col` is omitted, `.infer_scan_context_text_col()` checks for common
column names:

- `text`
- `context`
- `content`
- `chunk`
- `document`

If none exists, it uses the first character column. If there is no character
column, it errors.

Both string column names and bare column names are supported.

### Context Anomaly Detection

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

Synthetic anomaly findings use OWASP `llm08`, source `rules`, and
`synthetic = TRUE`. `.score_findings()` caps the combined synthetic
contribution at `0.3` per row before adding normal rule-finding scores.

### Trusted Sources

If a policy has `trusted_sources` and `source_col` is supplied, rows whose
source value is missing or outside the allowlist receive an
`llm08.untrusted_source` finding.

This finding has medium severity, `synthetic = TRUE`, and `action = "redact"`
by default. It does not automatically block the row. It contributes risk within
the synthetic scoring cap and lets normal action resolution decide.

### Context In `secure_chat()`

When `secure_chat()` receives context, it calls `scan_context()` and appends
only non-blocked context rows to the final prompt. Blocked rows trigger a
warning with the relevant rule ids and still appear in the audit trail through
`context_reports`.

## Feature Workflow: `scan_output()`

`scan_output()` is implemented in `R/scan_output.R`. It is the final scanner
before model text is displayed, stored, passed to a tool, or sent to another
workflow.

High-level purpose:

- Re-check model output for sensitive data or secrets.
- Catch unsafe code and command snippets.
- Catch agency claims, system-prompt leakage, and misinformation markers.
- Return a `shieldr_report`.

Detailed workflow:

1. Validate `text`, `policy`, `checks`, `reviewer`, and `show_tokens`.
2. Convert policy names to policy objects with `.as_policy()`.
3. Normalize Unicode with `stringi::stri_trans_nfkc()`.
4. Expand the policy with output-specific intrinsic rules through
   `.output_policy()`.
5. If `checks` is `rules` or `both`, extract fenced code blocks.
6. Scan fenced code blocks with `llm05.*` rules when code rules are available.
7. Offset code-block findings back to original output positions.
8. Scan the full output policy.
9. If `checks` is `nlp`, run NLP-only checks.
10. If `checks` is `llm` or `both` and a reviewer is supplied, run semantic
    review.
11. Deduplicate, score, resolve action, redact, and return a report.

### Output-Specific Policy Expansion

`.output_policy()` starts with the supplied policy, then adds output-specific
intrinsic rules when the policy does not already contain them:

- `.rule_code_safety()`
- `rule_agency_language()`
- `.rule_output_system_markers()`
- `rule_diagnosis_claim()`
- `.rule_misinformation_marker()`

This makes output scanning stricter than prompt scanning for code, agency,
system markers, and high-confidence unsupported claims.

### Fenced Code Block Pass

`.extract_fenced_code()` finds Markdown fenced code blocks such as:

````text
```r
system("rm -rf /")
```
````

The scanner extracts the content after the opening fence line, records the
1-based R character position where content begins, scans it with `llm05.*`
rules, then `.offset_findings()` maps finding spans back into the original
output string by adding `content_start - 1`.

The full output is scanned afterward, so code findings can be caught both in a
focused code pass and in the general output policy pass. Deduplication removes
identical duplicate findings.

## Feature Workflow: `secure_chat()`

`secure_chat()` is implemented in `R/secure_chat.R`. It is the primary
end-to-end orchestration function when a user already has a chat object or
chat function.

High-level purpose:

- Guard the input before a chat call.
- Optionally scan retrieved context and include only safe rows.
- Check resource limits.
- Call the model.
- Guard the output.
- Return a safe result with a full audit.

Detailed workflow:

1. Validate `prompt`.
2. Resolve the chat argument. `chat` is preferred; `provider =` in `...` is
   accepted as a backward-compatible alias.
3. Validate that the chat is a function or object with `$chat()`.
4. Convert policy names to policy objects.
5. Validate check mode, token display option, and reviewer.
6. Validate optional context.
7. Start elapsed-time timer.
8. Run `scan_prompt()`.
9. If prompt action is `block`, build an audit and return without calling chat.
10. If context is supplied, run `scan_context()`.
11. Warn when context rows are blocked and excluded.
12. Append only non-blocked context rows to the cleaned prompt.
13. Check the rate guard, if present.
14. If strict rate-guard mode is enabled, pre-debit an estimated prompt token
    cost.
15. Snapshot `ellmer::token_usage()` when token display is enabled.
16. Call the chat object or function.
17. Snapshot `ellmer::token_usage()` again.
18. Run `scan_output()` on raw model output.
19. Combine prompt and output actions.
20. Estimate token usage.
21. Update the rate guard with either the full estimate or the strict-mode
    positive delta.
22. Create `shieldr_audit()`.
23. Return `shieldr_result()`.

### Chat Argument Handling

`secure_chat()` accepts `chat` as the public argument. It also accepts
`provider =` through `...` as a backward-compatible alias.

`.validate_chat()` accepts:

- a plain function
- an object with a `$chat()` method

`.call_chat()` calls functions directly or delegates to `$chat()`. The return
value is collapsed to a single character string.

### Prompt Blocking

If the input report action is `block`, `secure_chat()` does not call the chat
object. It returns:

- `output = NULL`
- `action = "block"`
- an audit with `input_report`, no output report, no context reports, and a
  token estimate for the cleaned prompt

This is the main fail-closed path.

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

Blocked context rows are omitted and a warning is emitted with the triggered
rule ids. They still appear in the audit through `context_reports`.

### Final Action Combination

`.combine_actions()` applies conservative precedence:

1. `block`
2. `redact`
3. `allow`

If either the prompt or output blocks, the final result blocks. If either
redacts and neither blocks, the final result redacts.

### Returned Output

`shieldr_result$output` is:

- `NULL` when the final action is `block`
- `output_report$text_clean` when the final action is `allow` or `redact`

The raw model output remains available in `result$audit$output_raw`.

## Feature Workflow: `shield_ollama()`

`shield_ollama()` is implemented in `R/shield_ollama.R`.

High-level purpose:

- Provide a quick local-model path for users who use Ollama through `ellmer`.
- Keep assistant chat and reviewer chat separate.
- Delegate the actual safety workflow to `secure_chat()`.

Detailed workflow:

1. Check that `ellmer` is installed.
2. Validate `model`, `checks`, and `show_tokens`.
3. Create an assistant chat with `ellmer::chat_ollama(model = model)`.
4. If `checks` is `llm` or `both`, create a separate reviewer chat with the
   same model.
5. Call `secure_chat()` with the assistant chat, policy, reviewer, context, and
   token option.
6. Return the `shieldr_result`.

Keeping the reviewer chat separate prevents safety-review prompts from mixing
into the assistant conversation state.

For an existing chat object, users should call `secure_chat()` directly.

## Feature Workflow: `ollama_reviewer()`

`ollama_reviewer()` is a convenience helper for semantic review.

Workflow:

1. Check that `ellmer` is installed.
2. Validate `model`.
3. Call `ellmer::chat_ollama(model = model, ...)`.
4. Return the chat object.

The returned object can be passed to:

- `scan_prompt()`
- `scan_context()`
- `scan_output()`
- `secure_chat()`

Users are not required to use Ollama. Any reviewer function or chat object that
returns JSON findings can be used.

## Feature Workflow: `trust_boundary()`

`trust_boundary()` is implemented in `R/trust_boundary.R`.

High-level purpose:

- Validate application-level chat identity before calls cross into an LLM
  service.
- Support allowlists for model names and hosts.
- Optionally verify a local Ollama model manifest hash.

Detailed workflow:

1. Resolve `chat`, including the backward-compatible `provider =` alias.
2. Validate that `chat` is a function or object with `$chat()`.
3. Validate `allowed_models`, `allowed_hosts`, and `require_hash`.
4. Define an internal `validate()` function.
5. On wrapper creation, call `validate()`.
6. Return a function wrapper.
7. On each wrapper call, revalidate if `require_hash` is supplied or if the
   wrapper has not yet been validated.
8. If no call arguments are supplied, return the wrapped chat object.
9. If the chat is a function, call it directly.
10. Otherwise call `chat$chat(...)`.

### Model And Host Metadata

`.chat_model()` and `.chat_host()` inspect common locations:

- object attributes such as `model`, `base_url`, or `host`
- top-level list fields
- ellmer-style private fields inside `.__enclos_env__`

Plain functions pass through model and host checks because functions have no
standard model metadata.

### Host Matching

`.host_allowed()` accepts:

- exact host string
- URL-decoded host string
- host name after removing `http://` or `https://`
- host name before the first slash

### Ollama Hash Verification

When `require_hash` is supplied, the wrapper calls:

```text
ollama show --modelfile <model>
```

The call is made with `processx::run("ollama", c("show", "--modelfile",
model), error_on_status = FALSE)`, so the model name is passed as a separate
argument vector element instead of being interpolated into a shell command
string. The returned manifest text from `stdout` is hashed with SHA-256 through
`digest::digest()`. The hash is compared case-insensitively with
`require_hash`.

This function is not a network firewall. It is an application-level assertion
that the object being called is the intended object.

## Feature Workflow: `rate_guard()`

`rate_guard()` is implemented in `R/rate_guard.R`.

High-level purpose:

- Maintain request and token counters in a time window.
- Let policies enforce resource limits through `secure_chat()`.
- Cover resource-exhaustion concerns such as OWASP LLM10.

Creation mode:

```r
guard <- rate_guard(
  max_tokens = 100000,
  max_requests = 500,
  strict = TRUE,
  concurrent = TRUE
)
```

Workflow in creation mode:

1. Validate `max_tokens`, `max_requests`, `window_seconds`, `strict`, and
   `concurrent`.
2. Create a new environment with parent `emptyenv()`.
3. Store `.tokens_used`, `.requests_made`, `.window_start`, limits, and window
   length.
4. Store `.strict`, `.concurrent`, and an optional `.lock_path`.
5. Attach `$usage()` method.
6. Attach `$update(tokens, requests = 1L)` method.
7. Add class `shieldr_rate_guard`.
8. Return the environment.

Checking mode:

```r
rate_guard(guard)
```

Workflow in checking mode:

1. Validate that `session` inherits from `shieldr_rate_guard`.
2. Reset the window if it has expired.
3. Read usage through `$usage()`.
4. Error if token usage is above `max_tokens`.
5. Error if request count is above `max_requests`.
6. Return `TRUE` when limits are not exceeded.

The environment methods:

- `$usage()` resets the window if expired and returns counters and limits.
- `$update(tokens, requests = 1L)` resets if expired, increments token and
  request counters, and returns usage invisibly.

Limits set to `NULL` are disabled for that dimension.

With `strict = TRUE`, `secure_chat()` reserves an estimated prompt token cost
before the model call and then records only the positive difference between the
actual token estimate and the reserved amount afterward. This is useful when
multiple callers share one guard, but estimated tokens can differ from actual
usage.

With `concurrent = TRUE`, `$usage()` and `$update()` use `filelock::lock()` on
a temporary lock file. This provides file-based mutual exclusion on one
machine. Cross-machine coordination is not supported, and the default
`concurrent = FALSE` mode is not safe for shared parallel or async use.

## Feature Workflow: `write_audit_log()`

`write_audit_log()` is implemented in `R/audit.R`.

High-level purpose:

- Persist a `shieldr_audit` object for operational review.
- Support append-friendly and analysis-friendly formats.

Detailed workflow:

1. Validate that `audit` inherits from `shieldr_audit`.
2. Validate `path`.
3. Validate `format`, one of `jsonl`, `csv`, or `rds`.
4. Create the parent directory if it does not exist.
5. Write according to the selected format.
6. Return the path invisibly.

### JSONL Format

JSONL:

- appends one JSON object per line
- preserves nested audit structure better than CSV
- strips S3 classes and replaces environments with `"<environment>"`
- uses UTF-8 file writing

This is the preferred format for append-only production logs.

### CSV Format

CSV:

- flattens findings into one row per finding
- appends to existing files
- writes column names only when the file does not already exist
- includes stage, `context_row_index`, report index, action, risk score, rule
  id, OWASP category, severity, description, and source
- sets `context_row_index` to the 1-based context report position for
  context-stage findings and `NA` for input and output findings

CSV is convenient for spreadsheets and simple dashboards, but it loses nested
structure.

### RDS Format

RDS:

- saves the exact R object
- overwrites the target path
- warns before overwriting an existing file

Audit logs may contain sensitive text. The caller is responsible for storing
them in an appropriate location.

## Feature Workflow: `explain_findings()`

`explain_findings()` is implemented in `R/explain.R`.

High-level purpose:

- Format scanner findings for people.
- Preserve scanner decisions without rescoring or reclassifying anything.

Detailed workflow:

1. Validate that `findings` is a list.
2. Validate `format`, one of `text`, `markdown`, or `html`.
3. Return `character()` for an empty finding list.
4. Convert each finding to a readable line.
5. For `text`, print colored CLI bullets and return plain lines.
6. For `markdown`, return heading and bullet fragments per finding.
7. For `html`, escape rule ids, descriptions, matched text, and severity
   values before returning `<div>` fragments with severity classes.

This helper is suitable for console demos, Markdown reports, notebook output,
and simple dashboards.

## Feature Workflow: `example_prompts()`

`example_prompts()` is implemented in `R/example_data.R`.

High-level purpose:

- Provide a small teaching and testing corpus.
- Demonstrate clean, injection, PII, secret, agency, misinformation, context,
  and resource-exhaustion examples.
- Cover each OWASP LLM Top 10 category at least once.

Workflow:

1. Return a data frame with columns:
   - `feature`
   - `type`
   - `policy`
   - `prompt`
   - `expected_action`
2. The examples can be scanned directly in demos or tests.

The corpus is not a benchmark. It is a documentation, teaching, and regression
testing aid.

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

## Risk Summary

`.risk_summary()` collects findings from input, output, and context reports.

Workflow:

1. Recursively collect `shieldr_report` objects.
2. Extract findings from every report.
3. Extract OWASP category and severity from each finding.
4. Convert severity to score.
5. Group scores by OWASP category.
6. Sum each category.
7. Cap each category at `1.0`.
8. Return a named numeric vector.

Example conceptual output:

```text
llm01  1.0
llm02  0.6
llm08  0.3
```

This is useful for dashboards because it shows which OWASP category dominated a
run.

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

## Dependency Strategy

Required imports:

- `cli`: errors, warnings, console presentation.
- `digest`: SHA-256 hashing for trust-boundary model checks.
- `jsonlite`: semantic reviewer JSON parsing and audit JSON serialization.
- `rlang`: dependency checks.
- `stringi`: Unicode normalization.

Suggested packages:

- `ellmer`: Ollama chat objects and token usage.
- `processx`: optional Ollama model manifest hash checks.
- `filelock`: optional concurrent `rate_guard()` locking.
- `htmltools`: optional HTML escaping for finding explanations.
- `httr2`: reserved for future HTTP-oriented integrations.
- `tokenizers`: optional NLP tokenization.
- `SnowballC`: optional stemming.
- `testthat`: tests.
- `knitr` and `rmarkdown`: vignettes.
- `withr` and `dplyr`: development/testing support.

The package intentionally keeps local NLP and Ollama features optional. Users
who only want regex rules and scanner reports do not need those packages.

## File-Level Design Reference

- `R/rules.R`: S3 constructors, built-in rule helpers, reviewer prompt helper,
  severity scoring, validation helpers, NLP token/stem helpers.
- `R/policy.R`: built-in policy assembly, policy inventory, add/remove/list
  rule helpers.
- `R/scan_prompt.R`: prompt scanner, rule runner, NLP runner, semantic review,
  normalization, redaction, aggregate scoring, deduplication.
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
- `demo/demo.R`: package demo.
- `vignettes/*.Rmd`: user-facing long-form examples.
- `tests/testthat/*.R`: behavior-focused test suite.

## Workflow Diagrams

### Scanner Workflow

```text
text
  |
  v
validate inputs
  |
  v
normalize
  |
  v
run selected checks
  |
  v
dedupe findings
  |
  v
score findings
  |
  v
resolve action
  |
  v
redact spans
  |
  v
shieldr_report
```

### Secure Chat Workflow

```text
prompt + policy + chat
  |
  v
scan_prompt()
  |
  +-- block --> shieldr_result(output = NULL, audit, action = "block")
  |
  v
scan_context() when context is supplied
  |
  v
warn if context rows were blocked
  |
  v
append non-blocked context
  |
  v
rate_guard() check
  |
  v
strict pre-call reservation if enabled
  |
  v
chat call
  |
  v
scan_output()
  |
  v
combine actions
  |
  v
token estimate + rate_guard update
  |
  v
shieldr_audit
  |
  v
shieldr_result
```

### RAG Context Workflow

```text
context data frame
  |
  v
infer text column
  |
  v
compute length and instruction-density z-scores
  |
  v
for each row:
    create synthetic llm08 findings
    scan row text with scan_prompt()
    merge findings
    resolve row action
  |
  v
row-aligned list of shieldr_report objects
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

Recommended maintainer checks after scanner or policy changes:

```r
devtools::test()
devtools::document()
```

For documentation-only changes, reviewing Markdown rendering and any examples
that were edited is usually enough.

## Extension Points

Users can extend the package in several ways.

### Add Regex Rules

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

### Add Function Rules

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

### Build A Policy From Scratch

```r
guardrails <- build_policy(
  name = "support_team",
  rules = list(
    rule_pii_email(),
    rule_pii_phone(),
    rule_secrets_api_key()
  ),
  thresholds = list(redact_at = 0.3, block_at = 0.7)
)
```

### Use Any Chat Function

```r
chat <- function(prompt) {
  paste("MODEL RESPONSE:", prompt)
}

secure_chat("hello", chat = chat)
```

### Use Any Reviewer Function

```r
reviewer <- function(prompt) {
  "[]"
}

scan_prompt("hello", reviewer = reviewer, checks = "llm")
```

### Add Trusted Sources For RAG

```r
guardrails <- policy(
  "enterprise_default",
  overrides = list(trusted_sources = c("handbook", "kb-prod"))
)

scan_context(
  context_df,
  text_col = "text",
  source_col = "source",
  policy = guardrails
)
```

## Maintainer Guidelines

When adding a new rule:

- Use a stable id with the OWASP category prefix when possible.
- Choose the narrowest practical pattern.
- Set severity according to impact, not just match frequency.
- Use `action = "block"` only for cases that should fail closed.
- Add tests for clean text, matching text, and expected action.
- Prefer regex rules when redaction spans matter.
- Prefer function rules when the logic needs multiple conditions or derived
  features.

When adding a new policy:

- Assemble it from existing rule helpers where possible.
- Document thresholds and why they differ from defaults.
- Add it to `.built_in_policy_info()`.
- Add tests for `policy()`, `available_policies()`, and representative scanner
  behavior.

When changing scanner behavior:

- Preserve the `shieldr_report` contract.
- Preserve soft-failure behavior for optional reviewer and token integrations.
- Keep findings explainable.
- Avoid hidden model dependencies in deterministic scanner paths.
- Update this document and vignettes if user-facing behavior changes.

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
- `rate_guard(concurrent = TRUE)` uses a local file lock for one-machine
  coordination, but cross-machine coordination is not supported.
- Context anomaly detection is intentionally simple and should be treated as a
  signal, not proof of malicious context.

## Glossary

- Action: scanner decision, one of `allow`, `redact`, or `block`.
- Audit: end-to-end record of prompt, context, output, timing, tokens, reports,
  and final action.
- Check mode: scanner mode, one of `rules`, `nlp`, `llm`, or `both`.
- Finding: a single detected issue with rule metadata and optional match span.
- Policy: named set of rules, thresholds, optional rate guard, and optional
  trusted-source allowlist.
- Redaction span: character range replaced by `[REDACTED]`.
- Reviewer: optional function or chat object asked to return JSON findings.
- Risk score: deterministic severity sum capped at `1.0`, with synthetic
  context findings capped at `0.3` before normal rule scores are added.
- Rule: regex or function detector that produces findings.
- Trust boundary: application-level validation wrapper around a chat object.

## Final Architecture Summary

`llmshieldr` deliberately favors explicit control flow over hidden machinery.
Policies create rule sets. Scanners turn text into findings. Findings become
scores. Scores and rule actions become `allow`, `redact`, or `block`.
`secure_chat()` composes those pieces around a model call and returns a result
plus an audit trail.

That simple chain is the package's core design promise: safety decisions should
be inspectable, testable, and explainable as ordinary R objects.
