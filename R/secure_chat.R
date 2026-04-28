#' Run a guarded chat call
#'
#' Orchestrates prompt scanning, optional context scanning, provider execution,
#' output scanning, rate guarding, and audit creation.
#'
#' @details
#' `secure_chat()` is the main end-to-end workflow for users who already have a
#' provider. The provider can be a plain R function or an object with a
#' `$chat()` method. The function executes these steps:
#'
#' 1. Scan the prompt with [scan_prompt()].
#' 2. If the prompt is blocked, return a [shieldr_result()] without calling the
#'    provider.
#' 3. If context is supplied, scan it with [scan_context()] and append only
#'    non-blocked context rows to the cleaned prompt.
#' 4. Check the policy rate guard, if present.
#' 5. Call the provider.
#' 6. Scan provider output with [scan_output()].
#' 7. Resolve the final action, update the rate guard, and build an audit.
#'
#' The returned `risk_summary` aggregates finding severity scores by OWASP
#' category across prompt, context, and output reports. The final action is the
#' most conservative action across input and output: `block` beats `redact`,
#' and `redact` beats `allow`.
#'
#' @param prompt User prompt.
#' @param provider A provider function or object with `$chat()`.
#' @param policy A `shieldr_policy`.
#' @param reviewer Optional reviewer function or object with `$chat()`.
#' @param checks One of `"rules"`, `"llm"`, or `"both"`.
#' @param context Optional data frame of retrieved context.
#'
#' @return A `shieldr_result`.
#' @examples
#' provider <- function(prompt) "safe answer"
#' secure_chat("hello", provider, policy_preset("enterprise_default"))
#' @export
secure_chat <- function(prompt,
                        provider,
                        policy,
                        reviewer = NULL,
                        checks = "rules",
                        context = NULL) {
  .check_string(prompt, "prompt", allow_empty = TRUE)
  if (!is.function(provider) && !.has_chat_method(provider)) {
    cli::cli_abort("{.arg provider} must be a function or expose a {.code $chat()} method.")
  }
  .check_policy(policy)
  checks <- .validate_checks(checks)
  .validate_reviewer(reviewer)
  if (!is.null(context) && !is.data.frame(context)) {
    cli::cli_abort("{.arg context} must be a data frame or {.code NULL}.")
  }

  t0 <- proc.time()[["elapsed"]]
  input_report <- scan_prompt(prompt, policy, reviewer = reviewer, checks = checks)

  if (identical(input_report$action, "block")) {
    audit <- shieldr_audit(
      input_report = input_report,
      output_report = NULL,
      context_reports = NULL,
      prompt_clean = input_report$text_clean,
      output_raw = NULL,
      elapsed_ms = .elapsed_ms(t0),
      token_estimate = .estimate_tokens(input_report$text_clean),
      action = "block"
    )
    return(shieldr_result(
      output = NULL,
      audit = audit,
      risk_summary = .risk_summary(input_report),
      action = "block"
    ))
  }

  context_reports <- NULL
  final_prompt <- input_report$text_clean
  if (!is.null(context)) {
    text_col <- .infer_context_text_col(context)
    source_col <- if ("source" %in% names(context)) "source" else NULL
    context_reports <- scan_context(
      context,
      text_col = text_col,
      policy = policy,
      reviewer = reviewer,
      checks = checks,
      source_col = source_col
    )
    safe_idx <- which(vapply(context_reports, function(report) report$action, character(1)) != "block")
    if (length(safe_idx) > 0L) {
      safe_text <- vapply(context_reports[safe_idx], function(report) report$text_clean, character(1))
      final_prompt <- paste(
        input_report$text_clean,
        "Context:",
        paste(safe_text, collapse = "\n\n"),
        sep = "\n\n"
      )
    }
  }

  if (!is.null(policy$rate_guard)) {
    rate_guard(policy$rate_guard)
  }

  raw_output <- .call_provider(provider, final_prompt)
  output_report <- scan_output(raw_output, policy, reviewer = reviewer, checks = checks)
  final_action <- .combine_actions(input_report$action, output_report$action)

  token_estimate <- .estimate_tokens(final_prompt, raw_output)
  if (!is.null(policy$rate_guard)) {
    policy$rate_guard$update(tokens = token_estimate, cost_usd = 0)
  }

  audit <- shieldr_audit(
    input_report = input_report,
    output_report = output_report,
    context_reports = context_reports,
    prompt_clean = final_prompt,
    output_raw = raw_output,
    elapsed_ms = .elapsed_ms(t0),
    token_estimate = token_estimate,
    action = final_action
  )

  shieldr_result(
    output = if (identical(final_action, "block")) NULL else output_report$text_clean,
    audit = audit,
    risk_summary = .risk_summary(input_report, output_report, context_reports),
    action = final_action
  )
}

.call_provider <- function(provider, prompt) {
  out <- if (is.function(provider)) {
    provider(prompt)
  } else {
    provider$chat(prompt)
  }
  paste(as.character(out), collapse = "\n")
}

.combine_actions <- function(...) {
  actions <- c(...)
  if (any(actions == "block")) {
    return("block")
  }
  if (any(actions == "redact")) {
    return("redact")
  }
  "allow"
}

.estimate_tokens <- function(...) {
  text <- paste(c(...), collapse = " ")
  if (!nzchar(text)) {
    return(0L)
  }
  as.integer(ceiling(nchar(text, type = "chars") / 4))
}

.elapsed_ms <- function(t0) {
  as.numeric((proc.time()[["elapsed"]] - t0) * 1000)
}

.risk_summary <- function(...) {
  reports <- .collect_reports(list(...))
  findings <- unlist(lapply(reports, function(report) report$findings), recursive = FALSE)
  if (length(findings) == 0L) {
    return(stats::setNames(numeric(), character()))
  }
  owasp <- vapply(findings, function(finding) finding$owasp %||% NA_character_, character(1))
  scores <- vapply(findings, function(finding) .severity_score(finding$severity %||% "low"), numeric(1))
  keep <- !is.na(owasp) & nzchar(owasp)
  if (!any(keep)) {
    return(stats::setNames(numeric(), character()))
  }
  out <- tapply(scores[keep], owasp[keep], sum)
  pmin(out, 1)
}

.collect_reports <- function(x) {
  out <- list()
  for (item in x) {
    if (inherits(item, "shieldr_report")) {
      out[[length(out) + 1L]] <- item
    } else if (is.list(item)) {
      out <- c(out, .collect_reports(item))
    }
  }
  out
}

.infer_context_text_col <- function(context) {
  preferred <- c("text", "context", "content", "chunk", "document")
  hit <- preferred[preferred %in% names(context)]
  if (length(hit) > 0L) {
    return(hit[[1]])
  }
  chr_cols <- names(context)[vapply(context, is.character, logical(1))]
  if (length(chr_cols) == 0L) {
    cli::cli_abort("{.arg context} must contain at least one character column.")
  }
  chr_cols[[1]]
}
