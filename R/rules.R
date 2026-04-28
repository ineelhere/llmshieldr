#' Construct a `shieldr_rule`
#'
#' Creates a validated rule for the llmshieldr rule engine. Rules map to OWASP
#' LLM Top 10 categories where possible; see <https://genai.owasp.org/llm-top-10/>.
#'
#' @details
#' A rule is the atomic unit of a policy. Each rule either supplies a regular
#' expression pattern or an R function. Regex rules are applied with
#' `gregexpr(..., perl = TRUE)` and can produce character spans for redaction.
#' Function rules receive the full text and can return `TRUE`, `FALSE`, a
#' finding list, a list of finding lists, or a data frame of findings.
#'
#' `severity` is converted to a numeric score by the scanner:
#'
#' - `low`: `0.1`
#' - `medium`: `0.3`
#' - `high`: `0.6`
#' - `critical`: `1.0`
#'
#' The scanner caps the summed report score at `1.0`. Critical findings and
#' rules with `action = "block"` force the resolved report action to `block`.
#'
#' @param id A unique rule identifier.
#' @param pattern A regular expression pattern, or `NULL`.
#' @param fn A predicate function, or `NULL`.
#' @param owasp Optional OWASP LLM category such as `"llm01"`.
#' @param severity One of `"low"`, `"medium"`, `"high"`, or `"critical"`.
#' @param action One of `"allow"`, `"redact"`, or `"block"`.
#' @param description Human-readable rule description.
#'
#' @return A `shieldr_rule` S3 object.
#' @examples
#' shieldr_rule(
#'   id = "demo.email",
#'   pattern = "\\\\b[^@]+@example\\\\.com\\\\b",
#'   owasp = "llm02",
#'   description = "Example-domain email address"
#' )
#' @export
shieldr_rule <- function(id,
                         pattern = NULL,
                         fn = NULL,
                         owasp = NULL,
                         severity = "medium",
                         action = "redact",
                         description = "") {
  .check_string(id, "id")
  if (!is.null(pattern)) {
    .check_string(pattern, "pattern")
  }
  if (!is.null(fn) && !is.function(fn)) {
    cli::cli_abort("{.arg fn} must be a function or {.code NULL}.")
  }
  if (identical(is.null(pattern), is.null(fn))) {
    cli::cli_abort("Exactly one of {.arg pattern} or {.arg fn} must be supplied.")
  }
  if (!is.null(owasp)) {
    .check_string(owasp, "owasp")
  }
  .check_choice(severity, "severity", .shieldr_severities())
  .check_choice(action, "action", .shieldr_actions())
  .check_string(description, "description", allow_empty = TRUE)

  structure(
    list(
      id = id,
      pattern = pattern,
      fn = fn,
      owasp = if (is.null(owasp)) NULL else tolower(owasp),
      severity = severity,
      action = action,
      description = description
    ),
    class = "shieldr_rule"
  )
}

#' Construct a `shieldr_policy`
#'
#' Creates a validated policy from a list of `shieldr_rule` objects.
#'
#' @details
#' This is the low-level constructor. Most users should start with
#' [build_policy()] or [policy_preset()], which merge default thresholds and
#' assemble built-in rule lists. `shieldr_policy()` is exported so advanced
#' users and tests can construct exact policy objects.
#'
#' `trusted_sources` is used by [scan_context()] only. If it is `NULL`, all
#' sources are treated as trusted. If it is a character vector and `source_col`
#' is supplied to [scan_context()], rows with source values outside the allowlist
#' receive an OWASP LLM08 finding.
#'
#' @param name Policy name.
#' @param rules A list of `shieldr_rule` objects.
#' @param thresholds A list containing numeric `redact_at` and `block_at`
#'   values between 0 and 1.
#' @param rate_guard A `shieldr_rate_guard` environment, or `NULL`.
#' @param trusted_sources Optional character vector of trusted context sources.
#'
#' @return A `shieldr_policy` S3 object.
#' @examples
#' shieldr_policy("empty", list(), list(redact_at = 0.4, block_at = 0.75))
#' @export
shieldr_policy <- function(name,
                           rules,
                           thresholds,
                           rate_guard = NULL,
                           trusted_sources = NULL) {
  .check_string(name, "name")
  .check_rule_list(rules, "rules")
  thresholds <- .validate_thresholds(thresholds)
  .check_rate_guard(rate_guard)
  if (!is.null(trusted_sources) && !is.character(trusted_sources)) {
    cli::cli_abort("{.arg trusted_sources} must be a character vector or {.code NULL}.")
  }

  structure(
    list(
      name = name,
      rules = rules,
      thresholds = thresholds,
      rate_guard = rate_guard,
      trusted_sources = trusted_sources
    ),
    class = "shieldr_policy"
  )
}

#' Print a `shieldr_policy`
#'
#' @param x A `shieldr_policy`.
#' @param ... Unused.
#'
#' @return The policy, invisibly.
#' @export
print.shieldr_policy <- function(x, ...) {
  .check_policy(x)
  cli::cli_h1("llmshieldr policy")
  cli::cli_text("{.field name}: {x$name}")
  cli::cli_text("{.field rules}: {length(x$rules)}")
  table <- data.frame(
    threshold = c("redact_at", "block_at"),
    value = c(x$thresholds$redact_at, x$thresholds$block_at)
  )
  print(table, row.names = FALSE)
  invisible(x)
}

#' Construct a `shieldr_report`
#'
#' A `shieldr_report` is the scanner result returned by [scan_prompt()],
#' [scan_context()], and [scan_output()].
#'
#' @details
#' Reports separate the cleaned text from the findings that explain why the
#' text was allowed, redacted, or blocked. `risk_score` is a deterministic
#' severity index from `0` to `1`; it is not a probability. The `checks` field
#' records whether the report came from deterministic rules, an LLM reviewer,
#' or both.
#'
#' @param action Resolved action: `"allow"`, `"redact"`, or `"block"`.
#' @param text_clean Cleaned or redacted text.
#' @param findings A list of finding lists.
#' @param risk_score Numeric risk score between 0 and 1.
#' @param policy Policy name.
#' @param checks Check mode used.
#' @param timestamp ISO8601 timestamp.
#'
#' @return A `shieldr_report` S3 object.
#' @examples
#' shieldr_report("allow", "hello", list(), 0, "custom", "rules")
#' @export
shieldr_report <- function(action,
                           text_clean,
                           findings,
                           risk_score,
                           policy,
                           checks,
                           timestamp = .now_iso()) {
  .check_choice(action, "action", .shieldr_actions())
  .check_string(text_clean, "text_clean", allow_empty = TRUE)
  if (!is.list(findings)) {
    cli::cli_abort("{.arg findings} must be a list.")
  }
  .check_number_between(risk_score, "risk_score", 0, 1)
  .check_string(policy, "policy")
  .check_string(checks, "checks")
  .check_string(timestamp, "timestamp")

  structure(
    list(
      action = action,
      text_clean = text_clean,
      findings = findings,
      risk_score = risk_score,
      policy = policy,
      checks = checks,
      timestamp = timestamp
    ),
    class = "shieldr_report"
  )
}

#' Print a `shieldr_report`
#'
#' @param x A `shieldr_report`.
#' @param ... Unused.
#'
#' @return The report, invisibly.
#' @export
print.shieldr_report <- function(x, ...) {
  .check_report(x, allow_null = FALSE)
  colour <- switch(
    x$action,
    allow = cli::col_green,
    redact = cli::col_yellow,
    block = cli::col_red
  )
  cli::cli_h1("llmshieldr report")
  cli::cli_text("{.field action}: {colour(x$action)}")
  cli::cli_text("{.field risk_score}: {format(round(x$risk_score, 3), nsmall = 3)}")
  cli::cli_text("{.field findings}: {length(x$findings)}")
  invisible(x)
}

#' Construct a `shieldr_audit`
#'
#' Audits collect the scanner reports and operational metadata from a guarded
#' run.
#'
#' @details
#' [secure_chat()] builds this object automatically. `elapsed_ms` captures
#' wall-clock elapsed time for the guarded workflow. `token_estimate` is a
#' lightweight heuristic based on character count, currently
#' `ceiling(nchar(text) / 4)` over prompt and output text. It is intended for
#' guardrails and trend monitoring, not provider billing reconciliation.
#'
#' @param input_report A `shieldr_report`, or `NULL`.
#' @param output_report A `shieldr_report`, or `NULL`.
#' @param context_reports A list of `shieldr_report` objects, or `NULL`.
#' @param prompt_clean Cleaned prompt.
#' @param output_raw Raw provider output, or `NULL`.
#' @param elapsed_ms Elapsed time in milliseconds.
#' @param token_estimate Integer token estimate.
#' @param action Final action.
#'
#' @return A `shieldr_audit` S3 object.
#' @examples
#' shieldr_audit(NULL, NULL, NULL, "hello", NULL, 0, 1L, "allow")
#' @export
shieldr_audit <- function(input_report = NULL,
                          output_report = NULL,
                          context_reports = NULL,
                          prompt_clean,
                          output_raw = NULL,
                          elapsed_ms,
                          token_estimate,
                          action) {
  .check_report(input_report, allow_null = TRUE)
  .check_report(output_report, allow_null = TRUE)
  if (!is.null(context_reports)) {
    .check_report_list(context_reports, "context_reports")
  }
  .check_string(prompt_clean, "prompt_clean", allow_empty = TRUE)
  if (!is.null(output_raw)) {
    .check_string(output_raw, "output_raw", allow_empty = TRUE)
  }
  .check_number_between(elapsed_ms, "elapsed_ms", 0, Inf)
  if (!(is.numeric(token_estimate) && length(token_estimate) == 1L && !is.na(token_estimate))) {
    cli::cli_abort("{.arg token_estimate} must be a single integer-like value.")
  }
  .check_choice(action, "action", .shieldr_actions())

  structure(
    list(
      input_report = input_report,
      output_report = output_report,
      context_reports = context_reports,
      prompt_clean = prompt_clean,
      output_raw = output_raw,
      elapsed_ms = elapsed_ms,
      token_estimate = as.integer(token_estimate),
      action = action
    ),
    class = "shieldr_audit"
  )
}

#' Construct a `shieldr_result`
#'
#' A `shieldr_result` is the high-level return value from [secure_chat()] and
#' [shield_ollama()].
#'
#' @details
#' `output` is `NULL` when the final action is `block`; otherwise it contains
#' the cleaned model output. `risk_summary` aggregates finding severity scores
#' by OWASP category across prompt, context, and output reports, capping each
#' category at `1.0`. This gives dashboards and audit logs a compact view of
#' which OWASP categories were triggered.
#'
#' @param output Cleaned provider output, or `NULL`.
#' @param audit A `shieldr_audit` object.
#' @param risk_summary Named numeric vector keyed by OWASP category.
#' @param action Final action.
#'
#' @return A `shieldr_result` S3 object.
#' @examples
#' aud <- shieldr_audit(NULL, NULL, NULL, "hello", NULL, 0, 1L, "allow")
#' shieldr_result(NULL, aud, numeric(), "allow")
#' @export
shieldr_result <- function(output = NULL,
                           audit,
                           risk_summary,
                           action) {
  if (!is.null(output)) {
    .check_string(output, "output", allow_empty = TRUE)
  }
  if (!inherits(audit, "shieldr_audit")) {
    cli::cli_abort("{.arg audit} must be a {.cls shieldr_audit}.")
  }
  if (!is.numeric(risk_summary)) {
    cli::cli_abort("{.arg risk_summary} must be a named numeric vector.")
  }
  .check_choice(action, "action", .shieldr_actions())

  structure(
    list(
      output = output,
      audit = audit,
      risk_summary = risk_summary,
      action = action
    ),
    class = "shieldr_result"
  )
}

#' Built-in rule helpers
#'
#' Helpers create common OWASP LLM Top 10 guardrail rules for prompts, retrieved
#' context, and model outputs.
#'
#' @details
#' The helpers are intentionally small wrappers around [shieldr_rule()]. They
#' form the source rule bank used by [policy_preset()]. Each helper encodes one
#' common class of risk, such as prompt injection, PII, secrets, excessive
#' agency, system-prompt extraction, diagnosis claims, or financial advice.
#'
#' The rules are conservative defaults, not exhaustive detectors. They are
#' designed to be readable, testable, and easy to replace with organization-
#' specific rules when needed.
#'
#' @return A `shieldr_rule`.
#' @examples
#' rule_injection_basic()
#' rule_pii_email()
#' @name builtin_rules
NULL

#' @rdname builtin_rules
#' @export
rule_injection_basic <- function() {
  shieldr_rule(
    id = "llm01.injection.basic",
    pattern = paste(
      "(?i)",
      "ignore\\s+(all\\s+)?(previous|prior|above)\\s+(instructions|rules)|",
      "disregard\\s+(all\\s+)?(previous|prior|above)|",
      "forget\\s+(all\\s+)?(previous|prior|above)|",
      "override\\s+(the\\s+)?(system|developer)?\\s*instructions|",
      "\\bjailbreak\\b|do\\s+anything\\s+now|\\bDAN\\b",
      sep = ""
    ),
    owasp = "llm01",
    severity = "critical",
    action = "block",
    description = "Direct prompt-injection or jailbreak language."
  )
}

#' @rdname builtin_rules
#' @export
rule_injection_indirect <- function() {
  shieldr_rule(
    id = "llm01.injection.indirect",
    pattern = paste(
      "(?i)",
      "hidden\\s+instruction|instructions\\s+for\\s+(the\\s+)?(assistant|model)|",
      "when\\s+(you|the\\s+assistant)\\s+(read|see)\\s+this|",
      "(assistant|model)\\s+must\\s+ignore|",
      "^\\s*(system|developer)\\s*:",
      sep = ""
    ),
    owasp = "llm01",
    severity = "critical",
    action = "block",
    description = "Indirect prompt-injection content inside supplied text."
  )
}

#' @rdname builtin_rules
#' @export
rule_pii_email <- function() {
  shieldr_rule(
    id = "llm02.pii.email",
    pattern = "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b",
    owasp = "llm02",
    severity = "medium",
    action = "redact",
    description = "Email address."
  )
}

#' @rdname builtin_rules
#' @export
rule_pii_phone <- function() {
  shieldr_rule(
    id = "llm02.pii.phone",
    pattern = "\\b(?:\\+?1[-.\\s]?)?\\(?\\d{3}\\)?[-.\\s]?\\d{3}[-.\\s]?\\d{4}\\b",
    owasp = "llm02",
    severity = "medium",
    action = "redact",
    description = "US-style phone number."
  )
}

#' @rdname builtin_rules
#' @export
rule_pii_ssn <- function() {
  shieldr_rule(
    id = "llm02.pii.ssn",
    pattern = "\\b\\d{3}-\\d{2}-\\d{4}\\b",
    owasp = "llm02",
    severity = "high",
    action = "redact",
    description = "US Social Security number pattern."
  )
}

#' @rdname builtin_rules
#' @export
rule_secrets_api_key <- function() {
  shieldr_rule(
    id = "llm02.secret.api_key",
    pattern = paste(
      "(?i)",
      "\\bsk-[A-Za-z0-9]{20,}\\b|",
      "\\b(api[_-]?key|api[_-]?secret|secret[_-]?key)\\s*[:=]\\s*['\"]?[A-Za-z0-9_\\-]{16,}",
      sep = ""
    ),
    owasp = "llm02",
    severity = "high",
    action = "redact",
    description = "API key or API secret literal."
  )
}

#' @rdname builtin_rules
#' @export
rule_secrets_bearer <- function() {
  shieldr_rule(
    id = "llm02.secret.bearer",
    pattern = "\\bBearer\\s+[A-Za-z0-9._~+/=-]{20,}\\b",
    owasp = "llm02",
    severity = "high",
    action = "redact",
    description = "Bearer token."
  )
}

#' @rdname builtin_rules
#' @export
rule_secrets_aws <- function() {
  shieldr_rule(
    id = "llm02.secret.aws",
    pattern = "\\bAKIA[A-Z0-9]{16}\\b",
    owasp = "llm02",
    severity = "high",
    action = "redact",
    description = "AWS access key ID."
  )
}

#' @rdname builtin_rules
#' @export
rule_agency_language <- function() {
  shieldr_rule(
    id = "llm06.agency.language",
    pattern = paste(
      "(?i)",
      "\\bI\\s+will\\s+now\\b|\\bI\\s+have\\s+(sent|deleted|modified|notified|submitted)\\b|",
      "\\bI\\s+am\\s+granting\\b|\\bproceeding\\s+to\\b|\\bexecuting\\b",
      sep = ""
    ),
    owasp = "llm06",
    severity = "critical",
    action = "block",
    description = "Model claims or proposes autonomous agency."
  )
}

#' @rdname builtin_rules
#' @export
rule_system_prompt_leak <- function() {
  shieldr_rule(
    id = "llm07.system_prompt.extraction",
    pattern = paste(
      "(?i)",
      "(reveal|show|print|repeat|display)\\s+(your\\s+)?(system\\s+prompt|instructions|developer\\s+instructions)|",
      "what\\s+are\\s+your\\s+(system\\s+)?instructions",
      sep = ""
    ),
    owasp = "llm07",
    severity = "critical",
    action = "block",
    description = "System prompt extraction attempt."
  )
}

#' @rdname builtin_rules
#' @export
rule_diagnosis_claim <- function() {
  shieldr_rule(
    id = "llm09.diagnosis.claim",
    pattern = paste(
      "(?i)",
      "\\byou\\s+(have|are\\s+diagnosed\\s+with|should\\s+take)\\b|",
      "\\bdiagnosed\\s+with\\b|\\bdefinitely\\s+cures\\b|",
      "\\bthe\\s+only\\s+treatment\\b|\\b100%\\s+accurate\\b|\\bproven\\s+to\\b",
      sep = ""
    ),
    owasp = "llm09",
    severity = "critical",
    action = "block",
    description = "High-confidence diagnosis, treatment, or misinformation claim."
  )
}

#' @rdname builtin_rules
#' @export
rule_financial_advice <- function() {
  shieldr_rule(
    id = "llm09.financial.advice",
    pattern = paste(
      "(?i)",
      "\\byou\\s+should\\s+(buy|sell|short|invest)\\b|",
      "\\bguaranteed\\s+return\\b|\\brisk[- ]free\\s+investment\\b|",
      "\\bthis\\s+is\\s+financial\\s+advice\\b",
      sep = ""
    ),
    owasp = "llm09",
    severity = "high",
    action = "redact",
    description = "Financial advice or investment claim."
  )
}

.rule_secrets_connection_string <- function() {
  shieldr_rule(
    id = "llm02.secret.connection_string",
    pattern = "(?i)\\b(server|host|data\\s+source)\\s*=\\s*[^;]+;.*\\b(uid|user\\s*id|password|pwd)\\s*=",
    owasp = "llm02",
    severity = "high",
    action = "redact",
    description = "Connection string with credential fields."
  )
}

.rule_pii_mrn <- function() {
  shieldr_rule(
    id = "llm02.pii.mrn",
    pattern = "\\bMRN-[0-9]+\\b",
    owasp = "llm02",
    severity = "high",
    action = "redact",
    description = "Medical record number pattern."
  )
}

.rule_pii_usubjid <- function() {
  shieldr_rule(
    id = "llm02.pii.usubjid",
    pattern = "\\bUSUSUBJID-[0-9]+\\b",
    owasp = "llm02",
    severity = "high",
    action = "redact",
    description = "Clinical trial subject identifier pattern."
  )
}

.rule_code_safety <- function() {
  shieldr_rule(
    id = "llm05.code.safety",
    pattern = paste(
      "(?i)",
      "rm\\s+-rf\\s+/|curl\\s+.+\\|\\s*sh|Invoke-Expression|",
      "eval\\s*\\(|system\\s*\\(|shell\\s*\\(|",
      "DROP\\s+TABLE|DELETE\\s+FROM\\s+.+WHERE\\s+1\\s*=\\s*1",
      sep = ""
    ),
    owasp = "llm05",
    severity = "critical",
    action = "block",
    description = "Unsafe code or command pattern."
  )
}

.rule_account_number <- function() {
  shieldr_rule(
    id = "llm02.pii.account_number",
    pattern = "(?i)\\b(account|acct)\\s*(number|no\\.?|#)?\\s*[:=]?\\s*\\d{8,17}\\b",
    owasp = "llm02",
    severity = "high",
    action = "redact",
    description = "Bank or brokerage account number."
  )
}

.rule_coppa_minor_pii <- function() {
  shieldr_rule(
    id = "llm02.pii.coppa.minor",
    pattern = "(?i)\\b(child|student|minor)\\b.{0,40}\\b(age|dob|birthday|address|school)\\b",
    owasp = "llm02",
    severity = "high",
    action = "redact",
    description = "Potential COPPA-related minor personal information."
  )
}

.rule_academic_integrity <- function() {
  shieldr_rule(
    id = "llm01.injection.academic_integrity",
    pattern = "(?i)\\b(write|complete|solve)\\s+(my\\s+)?(exam|quiz|assignment|homework)\\b|bypass\\s+plagiarism",
    owasp = "llm01",
    severity = "critical",
    action = "block",
    description = "Academic-integrity bypass request."
  )
}

.rule_output_system_markers <- function() {
  shieldr_rule(
    id = "llm07.system_prompt.marker",
    pattern = "(?i)(^|\\s)#\\s*System\\b|\\bYou\\s+are\\s+an\\s+AI\\b|\\bYour\\s+instructions\\b|\\b(system|developer)\\s*:",
    owasp = "llm07",
    severity = "critical",
    action = "block",
    description = "System-prompt structural marker in model output."
  )
}

.rule_misinformation_marker <- function() {
  shieldr_rule(
    id = "llm09.misinformation.marker",
    pattern = "(?i)\\b(guaranteed|definitely\\s+cures|the\\s+only\\s+treatment|100%\\s+accurate|proven\\s+to)\\b",
    owasp = "llm09",
    severity = "critical",
    action = "block",
    description = "High-confidence medical or financial misinformation marker."
  )
}

.shieldr_severities <- function() {
  c("low", "medium", "high", "critical")
}

.shieldr_actions <- function() {
  c("allow", "redact", "block")
}

.severity_score <- function(severity) {
  switch(
    severity,
    low = 0.1,
    medium = 0.3,
    high = 0.6,
    critical = 1.0,
    0
  )
}

.check_string <- function(x, arg, allow_empty = FALSE) {
  if (!(is.character(x) && length(x) == 1L && !is.na(x))) {
    cli::cli_abort("{.arg {arg}} must be a single string.")
  }
  if (!allow_empty && !nzchar(x)) {
    cli::cli_abort("{.arg {arg}} must not be empty.")
  }
  invisible(TRUE)
}

.check_choice <- function(x, arg, choices) {
  .check_string(x, arg)
  if (!x %in% choices) {
    cli::cli_abort("{.arg {arg}} must be one of {.val {choices}}.")
  }
  invisible(TRUE)
}

.check_number_between <- function(x, arg, lower, upper) {
  if (!(is.numeric(x) && length(x) == 1L && !is.na(x) && x >= lower && x <= upper)) {
    cli::cli_abort("{.arg {arg}} must be a number between {lower} and {upper}.")
  }
  invisible(TRUE)
}

.check_rule_list <- function(rules, arg = "rules") {
  if (!is.list(rules)) {
    cli::cli_abort("{.arg {arg}} must be a list.")
  }
  bad <- !vapply(rules, inherits, logical(1), what = "shieldr_rule")
  if (any(bad)) {
    cli::cli_abort("Every element of {.arg {arg}} must be a {.cls shieldr_rule}.")
  }
  invisible(TRUE)
}

.check_policy <- function(policy) {
  if (!inherits(policy, "shieldr_policy")) {
    cli::cli_abort("{.arg policy} must be a {.cls shieldr_policy}.")
  }
  invisible(TRUE)
}

.check_report <- function(report, allow_null = FALSE) {
  if (is.null(report) && allow_null) {
    return(invisible(TRUE))
  }
  if (!inherits(report, "shieldr_report")) {
    cli::cli_abort("Report inputs must be {.cls shieldr_report} objects.")
  }
  invisible(TRUE)
}

.check_report_list <- function(reports, arg = "reports") {
  if (!is.list(reports)) {
    cli::cli_abort("{.arg {arg}} must be a list.")
  }
  bad <- !vapply(reports, inherits, logical(1), what = "shieldr_report")
  if (any(bad)) {
    cli::cli_abort("Every element of {.arg {arg}} must be a {.cls shieldr_report}.")
  }
  invisible(TRUE)
}

.check_rate_guard <- function(rate_guard) {
  if (!is.null(rate_guard) && !inherits(rate_guard, "shieldr_rate_guard")) {
    cli::cli_abort("{.arg rate_guard} must be a {.cls shieldr_rate_guard} environment or {.code NULL}.")
  }
  invisible(TRUE)
}

.validate_thresholds <- function(thresholds) {
  if (!is.list(thresholds)) {
    cli::cli_abort("{.arg thresholds} must be a list.")
  }
  if (is.null(thresholds$redact_at) || is.null(thresholds$block_at)) {
    cli::cli_abort("{.arg thresholds} must contain {.field redact_at} and {.field block_at}.")
  }
  .check_number_between(thresholds$redact_at, "thresholds$redact_at", 0, 1)
  .check_number_between(thresholds$block_at, "thresholds$block_at", 0, 1)
  if (thresholds$redact_at > thresholds$block_at) {
    cli::cli_abort("{.field redact_at} must be less than or equal to {.field block_at}.")
  }
  list(
    redact_at = as.numeric(thresholds$redact_at),
    block_at = as.numeric(thresholds$block_at)
  )
}

.now_iso <- function() {
  format(as.POSIXct(Sys.time(), tz = "UTC"), "%Y-%m-%dT%H:%M:%SZ", tz = "UTC")
}

.compact_chr <- function(x) {
  x <- as.character(x)
  x <- x[!is.na(x)]
  x[nzchar(x)]
}
