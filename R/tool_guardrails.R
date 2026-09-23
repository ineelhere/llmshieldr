#' Scan a tool call before execution
#'
#' `scan_tool_call()` validates tool-call intent and arguments before an
#' application executes the tool. It serializes the tool name and arguments,
#' scans that text with [scan_prompt()], and adds an explicit finding when the
#' tool is outside an allowlist. The default empty allowlist denies every tool.
#'
#' @details
#' This helper does not execute tools. It is designed to sit immediately before
#' an application-level dispatcher. Use `allowed_tools` for a simple allowlist,
#' and use normal policy rules or custom rules to validate argument content.
#'
#' The returned [shieldr_report()] stores `stage = "tool_call"` and `tool_name`
#' in `metadata`, so audit logs can distinguish tool input checks from prompt,
#' context, and output checks.
#'
#' @param tool_name Tool name requested by a model or orchestrator.
#' @param arguments Tool arguments as a list, data frame, character string, or
#'   other JSON-serializable value.
#' @param allowed_tools Character vector of approved tool names. The default
#'   empty vector denies every tool; `NULL` explicitly disables the allowlist.
#' @param tool_policy Optional richer policy from [tool_policy()].
#' @param subject Optional authorization context passed to the tool policy.
#' @param state Optional mutable call-limit state used by guarded dispatchers.
#' @param policy A `shieldr_policy` or built-in policy name.
#' @param reviewer Optional reviewer function or object with `$chat()`.
#' @param checks One of `"rules"`, `"nlp"`, `"llm"`, or `"both"`.
#' @param redaction Optional redaction strategy from [redaction_strategy()].
#' @param scanners Optional scanner configuration from [scanner_options()].
#' @param show_tokens Whether to attach token counts when `ellmer` is available.
#' @param show_stats Show execution statistics as messages.
#'
#' @return A `shieldr_report`.
#' @examples
#' report <- scan_tool_call(
#'   "send_email",
#'   list(to = "neel@example.com", body = "hello"),
#'   allowed_tools = c("search_docs", "send_email")
#' )
#'
#' report$action
#' @export
scan_tool_call <- function(tool_name,
                           arguments = list(),
                           allowed_tools = character(),
                           policy = "enterprise_default",
                           reviewer = NULL,
                           checks = "rules",
                           redaction = NULL,
                           scanners = scanner_options(),
                           show_tokens = FALSE,
                           tool_policy = NULL,
                           subject = NULL,
                           state = NULL,
                           show_stats = FALSE) {
  stats <- .stats_begin(show_stats, "scan_tool_call")
  on.exit(.stats_end(stats), add = TRUE)
  .check_string(tool_name, "tool_name")
  if (!is.null(allowed_tools) && !is.character(allowed_tools)) {
    cli::cli_abort("{.arg allowed_tools} must be a character vector or {.code NULL}.")
  }
  .validate_tool_policy(tool_policy, allow_null = TRUE)
  if (!is.null(state) && !is.environment(state)) {
    cli::cli_abort("{.arg state} must be an environment or {.code NULL}.")
  }

  policy_obj <- .as_policy(policy)
  payload <- .tool_call_text(tool_name, arguments)
  .stats_text_tokens(stats, payload)
  .stats_track_reviewer(stats, reviewer, checks)
  report <- scan_prompt(
    payload,
    policy = policy_obj,
    reviewer = reviewer,
    checks = checks,
    redaction = redaction,
    scanners = scanners,
    show_tokens = show_tokens,
    stage = "tool_call"
  )

  effective_policy <- .as_tool_policy(
    tool_policy,
    if (is.null(allowed_tools)) tool_name else allowed_tools
  )
  extra <- .tool_policy_findings(tool_name, arguments, effective_policy, subject, state)
  allowed <- length(extra) == 0L

  findings <- .dedupe_findings(c(extra, report$findings))
  risk_score <- .score_findings(findings)
  action <- .resolve_action(risk_score, findings, policy_obj)
  shieldr_report(
    action = action,
    text_clean = report$text_clean,
    findings = findings,
    risk_score = risk_score,
    policy = policy_obj$name,
    checks = checks,
    timestamp = report$timestamp,
    tokens = report$tokens,
    metadata = .report_metadata(
      stage = "tool_call",
      policy_version = policy_obj$version,
      policy_fingerprint = policy_obj$fingerprint,
      decision_schema_version = policy_obj$decision_schema_version,
      tool_name = tool_name,
      allowed = allowed,
      schema_checked = tool_name %in% names(effective_policy$schemas),
      authorization_checked = !is.null(effective_policy$authorize),
      call_count = if (is.null(state)) NULL else state$calls,
      side_effect_count = if (is.null(state)) NULL else state$side_effects,
      reviewer_errors = report$metadata$reviewer_errors %||% list(),
      review_status = report$metadata$review_status %||% "not_requested",
      reviewer_failure_action = report$metadata$reviewer_failure_action %||% NULL,
      scanners = scanners
    )
  )
}

#' Scan tool output before it re-enters model context
#'
#' `scan_tool_output()` checks text returned by tools before that text is shown
#' to a user, stored, or appended back into model context.
#'
#' @details
#' Tool outputs are scanned with [scan_output()] because they are untrusted
#' downstream content. The returned report stores `stage = "tool_output"` and
#' `tool_name` in `metadata`.
#'
#' @inheritParams scan_tool_call
#' @param output Tool output text or object coercible to text.
#'
#' @return A `shieldr_report`.
#' @examples
#' scan_tool_output("search_docs", "Result includes neel@example.com")
#' @export
scan_tool_output <- function(tool_name,
                             output,
                             policy = "enterprise_default",
                             reviewer = NULL,
                             checks = "rules",
                             redaction = NULL,
                             scanners = scanner_options(),
                             show_tokens = FALSE,
                             show_stats = FALSE) {
  stats <- .stats_begin(show_stats, "scan_tool_output")
  on.exit(.stats_end(stats), add = TRUE)
  .check_string(tool_name, "tool_name")
  text <- .tool_output_text(output)
  .stats_text_tokens(stats, text)
  .stats_track_reviewer(stats, reviewer, checks)
  report <- scan_output(
    text,
    policy = policy,
    reviewer = reviewer,
    checks = checks,
    redaction = redaction,
    scanners = scanners,
    show_tokens = show_tokens,
    stage = "tool_output"
  )
  report$metadata <- utils::modifyList(
    report$metadata %||% list(),
    .report_metadata(stage = "tool_output", tool_name = tool_name)
  )
  report
}

.tool_output_text <- function(output) {
  if (is.character(output) || is.atomic(output)) {
    return(paste(as.character(output), collapse = "\n"))
  }
  if (is.list(output) && !is.object(output)) {
    return(paste(vapply(output, .tool_output_text, character(1)), collapse = "\n"))
  }
  if (requireNamespace("S7", quietly = TRUE)) {
    text <- tryCatch(S7::prop(output, "text"), error = function(e) NULL)
    if (is.character(text) && length(text) == 1L && !is.na(text)) return(text)
  }
  cli::cli_abort("Tool output type is not safely scannable as text.")
}

.tool_call_text <- function(tool_name, arguments) {
  args <- tryCatch(
    jsonlite::toJSON(arguments, auto_unbox = TRUE, null = "null"),
    error = function(e) paste(as.character(arguments), collapse = "\n")
  )
  paste(
    "Tool call:",
    paste0("name: ", tool_name),
    "arguments:",
    as.character(args),
    sep = "\n"
  )
}
