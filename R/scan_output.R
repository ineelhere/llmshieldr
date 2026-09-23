#' Scan model output
#'
#' Scans LLM output for sensitive data, unsafe code, agency claims, system
#' prompt leakage, misinformation markers, and optional NLP intent signals.
#'
#' @details
#' Output scanning is the last guardrail before model text is displayed, stored,
#' or passed to another tool. It runs the policy rule set over the full output
#' and adds output-specific checks for common failure modes:
#'
#' - fenced code blocks are scanned for unsafe code and command patterns
#' - excessive-agency language such as "I will now" or "I have deleted"
#' - system-prompt structural markers such as "# System" or role declarations
#' - high-confidence medical or financial claim markers
#'
#' Agency checks in `checks = "rules"` match known phrases and action verbs;
#' they cannot infer every paraphrase or distinguish every quotation from a
#' model's own intent. For broader intent review, supply a semantic `reviewer`
#' with `checks = "both"` and evaluate it on your application data.
#'
#' Use `checks = "nlp"` when you want a lightweight local NLP-only pass over
#' model output. The return value is a [shieldr_report()] with the same scoring
#' and action semantics as [scan_prompt()].
#'
#' @param text Model output text.
#' @param policy A `shieldr_policy` or built-in policy name such as `"comprehensive"`.
#' @param reviewer Optional reviewer function or object with `$chat()`.
#' @param checks One of `"rules"`, `"nlp"`, `"llm"`, or `"both"`.
#' @param redaction Optional redaction strategy from [redaction_strategy()].
#' @param scanners Optional scanner configuration from [scanner_options()].
#' @param contract Optional destination contract from [output_contract()].
#' @param show_tokens Whether to attach token counts when `ellmer` is available.
#' @param show_stats Show elapsed time, token estimate, network status, and
#'   transfer metrics when available.
#' @param stage Internal trust-boundary stage.
#'
#' @return A `shieldr_report`.
#' @examples
#' scan_output("A concise answer.")
#' scan_output("A concise answer.", show_tokens = TRUE)
#' @export
scan_output <- function(text,
                        policy = "enterprise_default",
                        reviewer = NULL,
                        checks = "rules",
                         redaction = NULL,
                         scanners = scanner_options(),
                         contract = NULL,
                         show_tokens = FALSE,
                         stage = "output",
                         show_stats = FALSE) {
  stats <- .stats_begin(show_stats, "scan_output")
  on.exit(.stats_end(stats), add = TRUE)
  .stats_text_tokens(stats, text)
  .stats_track_reviewer(stats, reviewer, checks)
  .check_string(text, "text", allow_empty = TRUE)
  policy <- .as_policy(policy)
  checks <- .validate_checks(checks)
  redaction <- .validate_redaction_strategy(redaction)
  scanners <- .validate_scanner_options(scanners)
  .validate_output_contract(contract, allow_null = TRUE)
  show_tokens <- .validate_show_tokens(show_tokens)
  .validate_reviewer_for_checks(reviewer, checks)
  .check_choice(stage, "stage", c("output", "tool_output"))

  text_norm <- .normalise_text(text, collapse_whitespace = FALSE, collapse_delimited = FALSE)
  output_policy <- .output_policy(policy)
  findings <- list()
  reviewer_errors <- list()
  findings <- c(findings, .run_scanners(text, text_norm, output_policy, scanners, stage = stage))

  if (checks %in% c("rules", "both")) {
    code_blocks <- .extract_fenced_code(text_norm)
    if (length(code_blocks) > 0L) {
      code_rules <- Filter(function(rule) grepl("^llm05\\.", rule$id), output_policy$rules)
      if (length(code_rules) > 0L) {
        code_policy <- build_policy(
          name = paste0(output_policy$name, "_code"),
          rules = code_rules,
          thresholds = output_policy$thresholds
        )
        for (block in code_blocks) {
          block_findings <- .run_rules(block$text, code_policy, stage = stage)
          findings <- c(findings, .offset_findings(block_findings, block$offset - 1L))
        }
      }
    }
    findings <- c(findings, .run_rules(text_norm, output_policy, stage = stage))
  } else if (identical(checks, "nlp")) {
    findings <- c(findings, .run_nlp(text_norm, output_policy))
  }

  if (checks %in% c("llm", "both") && !is.null(reviewer)) {
    semantic <- .semantic_review(text_norm, reviewer, policy$name, policy$controls)
    reviewer_errors <- c(reviewer_errors, attr(semantic, "reviewer_errors") %||% list())
    findings <- c(findings, semantic)
  }
  if (length(reviewer_errors) > 0L &&
      policy$controls$on_reviewer_error %in% c("block", "escalate")) {
    findings <- c(findings, list(.reviewer_failure_finding()))
  }

  text_clean <- .apply_redaction(text_norm, findings, redaction)
  if (!is.null(contract)) {
    contracted <- .apply_output_contract(text_clean, contract)
    text_clean <- contracted$text
    findings <- c(findings, contracted$findings)
  }
  findings <- .dedupe_findings(findings)
  risk_score <- .score_findings(findings)
  action <- .resolve_action(risk_score, findings, output_policy)

  shieldr_report(
    action = action,
    text_clean = text_clean,
    findings = findings,
    risk_score = risk_score,
    policy = policy$name,
    checks = checks,
    tokens = if (isTRUE(show_tokens)) .count_tokens(text) else NULL,
    metadata = .report_metadata(
      stage = stage,
      policy_version = policy$version,
      policy_fingerprint = policy$fingerprint,
      decision_schema_version = policy$decision_schema_version,
      output_contract = if (is.null(contract)) NULL else contract$format,
      reviewer_errors = reviewer_errors,
      review_status = .review_status(checks, reviewer, reviewer_errors),
      reviewer_failure_action = if (length(reviewer_errors) > 0L) policy$controls$on_reviewer_error else NULL,
      scanners = scanners
    )
  )
}

.output_policy <- function(policy) {
  intrinsic <- list(
    .rule_code_safety(),
    rule_agency_language(),
    .rule_output_system_markers(),
    rule_diagnosis_claim(),
    .rule_misinformation_marker()
  )
  existing <- vapply(policy$rules, `[[`, character(1), "id")
  intrinsic <- intrinsic[!vapply(intrinsic, function(rule) rule$id %in% existing, logical(1))]
  shieldr_policy(
    name = policy$name,
    rules = c(policy$rules, intrinsic),
    thresholds = policy$thresholds,
    rate_guard = policy$rate_guard,
    trusted_sources = policy$trusted_sources,
    controls = policy$controls,
    version = policy$version
  )
}

.extract_fenced_code <- function(text) {
  matches <- gregexpr("```[[:alnum:]_+.-]*\\s*[\\s\\S]*?```", text, perl = TRUE)[[1]]
  if (length(matches) == 0L || identical(matches[[1]], -1L)) {
    return(list())
  }
  lengths <- attr(matches, "match.length")
  out <- vector("list", length(matches))
  for (i in seq_along(matches)) {
    start <- as.integer(matches[[i]])
    end <- start + as.integer(lengths[[i]]) - 1L
    raw <- substr(text, start, end)
    opening <- regexpr("^```[[:alnum:]_+.-]*[^\r\n]*(\r\n|\n|\r)?", raw, perl = TRUE)
    opening_length <- if (identical(as.integer(opening[[1]]), -1L)) 0L else as.integer(attr(opening, "match.length"))
    closing <- regexpr("(\r\n|\n|\r)?```\\s*$", raw, perl = TRUE)
    content_end <- if (identical(as.integer(closing[[1]]), -1L)) {
      nchar(raw)
    } else {
      as.integer(closing[[1]]) - 1L
    }
    content <- if (content_end >= opening_length + 1L) {
      substr(raw, opening_length + 1L, content_end)
    } else {
      ""
    }
    # R character positions are 1-based; offset points to the first content character.
    content_offset <- start + opening_length
    out[[i]] <- list(text = content, content = content, offset = content_offset)
  }
  out
}

.offset_findings <- function(findings, offset) {
  lapply(findings, function(finding) {
    # Findings use 1-based R character positions; offset is content_start - 1.
    if (!is.null(finding$start) && !is.na(finding$start)) {
      finding$start <- finding$start + offset
    }
    if (!is.null(finding$end) && !is.na(finding$end)) {
      finding$end <- finding$end + offset
    }
    finding
  })
}
