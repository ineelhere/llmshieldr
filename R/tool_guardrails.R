#' Scan a tool call before execution
#'
#' `scan_tool_call()` validates tool-call intent and arguments before an
#' application executes the tool. It serializes the tool name and arguments,
#' scans that text with [scan_prompt()], and adds an explicit finding when the
#' tool is outside an allowlist.
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
#' @param allowed_tools Optional character vector of approved tool names.
#' @param policy A `shieldr_policy` or built-in policy name.
#' @param reviewer Optional reviewer function or object with `$chat()`.
#' @param checks One of `"rules"`, `"nlp"`, `"llm"`, or `"both"`.
#' @param redaction Optional redaction strategy from [redaction_strategy()].
#' @param scanners Optional scanner configuration from [scanner_options()].
#' @param show_tokens Whether to attach token counts when `ellmer` is available.
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
                           allowed_tools = NULL,
                           policy = "enterprise_default",
                           reviewer = NULL,
                           checks = "rules",
                           redaction = NULL,
                           scanners = scanner_options(),
                           show_tokens = FALSE) {
  .check_string(tool_name, "tool_name")
  if (!is.null(allowed_tools) && !is.character(allowed_tools)) {
    cli::cli_abort("{.arg allowed_tools} must be a character vector or {.code NULL}.")
  }

  policy_obj <- .as_policy(policy)
  payload <- .tool_call_text(tool_name, arguments)
  report <- scan_prompt(
    payload,
    policy = policy_obj,
    reviewer = reviewer,
    checks = checks,
    redaction = redaction,
    scanners = scanners,
    show_tokens = show_tokens
  )

  extra <- list()
  allowed <- is.null(allowed_tools) || tool_name %in% allowed_tools
  if (!allowed) {
    extra[[1L]] <- .synthetic_finding(
      "llm06.tool.unapproved",
      "llm06",
      "critical",
      "Tool call targets a tool outside the configured allowlist.",
      action = "block"
    )
  }

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
      tool_name = tool_name,
      allowed = allowed,
      reviewer_errors = report$metadata$reviewer_errors %||% list(),
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
                             show_tokens = FALSE) {
  .check_string(tool_name, "tool_name")
  text <- paste(as.character(output), collapse = "\n")
  report <- scan_output(
    text,
    policy = policy,
    reviewer = reviewer,
    checks = checks,
    redaction = redaction,
    scanners = scanners,
    show_tokens = show_tokens
  )
  report$metadata <- utils::modifyList(
    report$metadata %||% list(),
    .report_metadata(stage = "tool_output", tool_name = tool_name)
  )
  report
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
