#' Run a guarded chat call
#'
#' Orchestrates prompt scanning, optional context scanning, chat execution,
#' output scanning, rate guarding, and audit creation.
#'
#' @details
#' `secure_chat()` is the main end-to-end workflow when you already have an
#' `ellmer` chat object or another object with a `$chat()` method. Plain
#' functions are also accepted for small tests. The function executes these
#' steps:
#'
#' 1. Scan the prompt with [scan_prompt()].
#' 2. If the prompt is blocked, return a [shieldr_result()] without calling the chat.
#' 3. If context is supplied, scan it with [scan_context()] and append only
#'    allowed context rows to the cleaned prompt, using row IDs, source labels,
#'    and separators.
#' 4. Reserve request and token budget with the policy rate guard, if present.
#' 5. Call the chat object.
#' 6. Scan model output with [scan_output()].
#' 7. Resolve the final action, update the rate guard, and build an audit.
#'
#' The returned `risk_summary` aggregates finding severity scores by OWASP
#' category across prompt, context, and output reports. The final action is the
#' most conservative action across input and output: `block` beats `redact`,
#' and `redact` beats `allow`. Policy controls can map blocked prompt or output
#' reports to final actions of `refuse` or `escalate`.
#'
#' @param prompt User prompt.
#' @param chat An `ellmer` chat object, an object with `$chat()`, or a function.
#' @param policy A `shieldr_policy` or built-in policy name such as `"comprehensive"`.
#' @param reviewer Optional reviewer function or object with `$chat()`.
#' @param checks One of `"rules"`, `"nlp"`, `"llm"`, or `"both"`.
#' @param context Optional data frame of retrieved context.
#' @param redaction Optional redaction strategy from [redaction_strategy()].
#' @param scanners Optional scanner configuration from [scanner_options()].
#' @param show_tokens Whether to attach token counts when `ellmer` is available.
#' @param ... Reserved for backwards-compatible aliases.
#'
#' @return A `shieldr_result`.
#' @examples
#' \dontrun{
#' model <- ellmer::models_ollama()$id[1]
#' if (is.na(model)) {
#'   stop(
#'     "Check if you have any Ollama models available, ",
#'     "or enter a specific name as a string for the model argument."
#'   )
#' }
#' chat <- ellmer::chat_ollama(model = model)
#' secure_chat("hello", chat, show_tokens = TRUE)
#' }
#' @export
secure_chat <- function(prompt,
                        chat = NULL,
                        policy = "enterprise_default",
                        reviewer = NULL,
                        checks = "rules",
                        context = NULL,
                        redaction = NULL,
                        scanners = scanner_options(),
                        show_tokens = FALSE,
                        ...) {
  .check_string(prompt, "prompt", allow_empty = TRUE)
  chat <- .resolve_chat_arg(chat, list(...))
  .validate_chat(chat)
  policy <- .as_policy(policy)
  checks <- .validate_checks(checks)
  redaction <- .validate_redaction_strategy(redaction)
  scanners <- .validate_scanner_options(scanners)
  show_tokens <- .validate_show_tokens(show_tokens)
  .validate_reviewer_for_checks(reviewer, checks)
  if (!is.null(context) && !is.data.frame(context)) {
    cli::cli_abort("{.arg context} must be a data frame or {.code NULL}.")
  }

  t0 <- proc.time()[["elapsed"]]
  input_report <- scan_prompt(
    prompt,
    policy,
    reviewer = reviewer,
    checks = checks,
    redaction = redaction,
    scanners = scanners,
    show_tokens = show_tokens
  )

  if (identical(input_report$action, "block")) {
    final_action <- policy$controls$on_prompt_block
    audit <- shieldr_audit(
      input_report = input_report,
      output_report = NULL,
      context_reports = NULL,
      prompt_clean = input_report$text_clean,
      output_raw = NULL,
      elapsed_ms = .elapsed_ms(t0),
      token_estimate = .count_tokens(input_report$text_clean),
      action = final_action
    )
    return(shieldr_result(
      output = .controlled_output(final_action, policy$controls),
      audit = audit,
      risk_summary = .risk_summary(input_report),
      action = final_action
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
      source_col = source_col,
      redaction = redaction,
      scanners = scanners,
      show_tokens = show_tokens
    )
    blocked_idx <- which(vapply(context_reports, function(report) report$action, character(1)) == "block")
    n_blocked <- length(blocked_idx)
    if (n_blocked > 0L) {
      rule_ids <- unique(.compact_chr(unlist(lapply(context_reports[blocked_idx], function(report) {
        vapply(report$findings, function(finding) finding$rule_id %||% NA_character_, character(1))
      }), use.names = FALSE)))
      if (length(rule_ids) == 0L) {
        rule_ids <- "<unknown>"
      }
      cli::cli_warn(c(
        "{n_blocked} context row{?s} blocked and excluded from prompt.",
        "i" = "Triggered rule{?s}: {.val {rule_ids}}."
      ))
    }
    if (n_blocked > 0L && policy$controls$on_context_block %in% c("block", "refuse", "escalate")) {
      final_action <- policy$controls$on_context_block
      audit <- shieldr_audit(
        input_report = input_report,
        output_report = NULL,
        context_reports = context_reports,
        prompt_clean = input_report$text_clean,
        output_raw = NULL,
        elapsed_ms = .elapsed_ms(t0),
        token_estimate = .count_tokens(input_report$text_clean),
        action = final_action
      )
      return(shieldr_result(
        output = .controlled_output(final_action, policy$controls),
        audit = audit,
        risk_summary = .risk_summary(input_report, context_reports),
        action = final_action
      ))
    }
    safe_idx <- if (identical(policy$controls$on_context_block, "keep_redacted")) {
      seq_along(context_reports)
    } else {
      which(vapply(context_reports, function(report) report$action, character(1)) != "block")
    }
    if (length(safe_idx) > 0L) {
      final_prompt <- .assemble_context_prompt(
        input_report$text_clean,
        context_reports = context_reports,
        keep = safe_idx
      )
    }
  }

  strict_estimate <- NULL
  reserved_tokens <- 0
  reserved_requests <- 0L
  if (!is.null(policy$rate_guard)) {
    if (isTRUE(policy$rate_guard$.strict)) {
      strict_estimate <- .count_tokens(final_prompt)
      policy$rate_guard$reserve(tokens = strict_estimate, requests = 1L)
      reserved_tokens <- strict_estimate
      reserved_requests <- 1L
    } else {
      policy$rate_guard$reserve(tokens = 0, requests = 1L)
      reserved_requests <- 1L
    }
  }

  chat_stage <- tryCatch(
    {
      usage_before <- if (isTRUE(show_tokens)) .ellmer_usage_snapshot() else NULL
      raw_output <- .call_chat(chat, final_prompt)
      usage_after <- if (isTRUE(show_tokens)) .ellmer_usage_snapshot() else NULL
      output_report <- scan_output(
        raw_output,
        policy,
        reviewer = reviewer,
        checks = checks,
        redaction = redaction,
        scanners = scanners,
        show_tokens = show_tokens
      )
      list(
        raw_output = raw_output,
        output_report = output_report,
        usage_before = usage_before,
        usage_after = usage_after
      )
    },
    error = function(e) {
      if (!is.null(policy$rate_guard) && (reserved_tokens > 0 || reserved_requests > 0L)) {
        policy$rate_guard$rollback(tokens = reserved_tokens, requests = reserved_requests)
      }
      stop(e)
    }
  )
  raw_output <- chat_stage$raw_output
  output_report <- chat_stage$output_report
  final_action <- .combine_actions(input_report$action, output_report$action)
  if (identical(output_report$action, "block")) {
    final_action <- policy$controls$on_output_block
  }

  token_estimate <- .ellmer_usage_delta(chat_stage$usage_before, chat_stage$usage_after) %||% .count_tokens(final_prompt, raw_output)
  if (!is.null(policy$rate_guard)) {
    if (isTRUE(policy$rate_guard$.strict)) {
      actual_delta <- token_estimate - (strict_estimate %||% .count_tokens(final_prompt))
      if (actual_delta > 0) {
        policy$rate_guard$update(tokens = actual_delta, requests = 0L)
      }
    } else {
      policy$rate_guard$update(tokens = token_estimate, requests = 0L)
    }
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
    output = if (final_action %in% c("block", "escalate")) NULL else .controlled_output(final_action, policy$controls) %||% output_report$text_clean,
    audit = audit,
    risk_summary = .risk_summary(input_report, output_report, context_reports),
    action = final_action
  )
}

.resolve_chat_arg <- function(chat, dots) {
  if (length(dots) == 0L) {
    if (is.null(chat)) {
      cli::cli_abort("{.arg chat} must be supplied.")
    }
    return(chat)
  }

  dot_names <- names(dots)
  if (is.null(dot_names)) {
    dot_names <- rep("", length(dots))
  }
  extra <- dot_names[!dot_names %in% "provider"]
  if (any(!nzchar(extra))) {
    cli::cli_abort("Unexpected unnamed arguments in {.arg ...}.")
  }
  if (length(extra) > 0L) {
    cli::cli_abort("Unexpected argument{?s} in {.arg ...}: {.arg {extra}}.")
  }
  if ("provider" %in% dot_names) {
    if (!is.null(chat)) {
      cli::cli_abort("Use {.arg chat} only once.")
    }
    chat <- dots$provider
  }
  if (is.null(chat)) {
    cli::cli_abort("{.arg chat} must be supplied.")
  }
  chat
}

.validate_chat <- function(chat, arg = "chat") {
  if (!is.function(chat) && !.has_chat_method(chat)) {
    cli::cli_abort("{.arg {arg}} must be an ellmer chat object, an object with {.code $chat()}, or a function.")
  }
  invisible(TRUE)
}

.call_chat <- function(chat, prompt) {
  out <- if (is.function(chat)) {
    chat(prompt)
  } else {
    chat$chat(prompt)
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

.count_tokens <- function(...) {
  text <- paste(c(...), collapse = " ")
  if (!nzchar(text)) {
    return(0L)
  }
  if (requireNamespace("ellmer", quietly = TRUE)) {
    token_fun <- NULL
    ns <- asNamespace("ellmer")
    candidates <- c("tokens", "token_count", "count_tokens", "tkn_count", "count_tokens")
    for (name in candidates) {
      if (exists(name, envir = ns, mode = "function")) {
        token_fun <- get(name, envir = ns, mode = "function")
        break
      }
    }
    if (!is.null(token_fun)) {
      result <- tryCatch(token_fun(text), error = function(e) NULL)
      if (is.numeric(result) && length(result) == 1L && !is.na(result)) {
        return(as.integer(result))
      }
      if (is.character(result)) {
        return(as.integer(length(result)))
      }
      if (is.list(result)) {
        return(as.integer(length(result)))
      }
    }
  }
  as.integer(ceiling(nchar(text, type = "chars") / 4))
}

.ellmer_usage_snapshot <- function() {
  if (!requireNamespace("ellmer", quietly = TRUE)) {
    return(NULL)
  }
  if (!exists("token_usage", envir = asNamespace("ellmer"), mode = "function")) {
    return(NULL)
  }
  usage <- tryCatch(
    suppressMessages(ellmer::token_usage()),
    error = function(e) NULL
  )
  if (is.data.frame(usage)) usage else NULL
}

.ellmer_usage_delta <- function(before, after) {
  if (!is.data.frame(after)) {
    return(NULL)
  }
  token_cols <- intersect(c("input", "output", "cached_input"), names(after))
  if (length(token_cols) == 0L) {
    return(NULL)
  }
  sum_tokens <- function(x) {
    if (!is.data.frame(x)) {
      return(0)
    }
    cols <- intersect(token_cols, names(x))
    if (length(cols) == 0L) {
      return(0)
    }
    values <- suppressWarnings(as.numeric(unlist(x[cols], use.names = FALSE)))
    sum(values, na.rm = TRUE)
  }
  delta <- sum_tokens(after) - sum_tokens(before)
  if (is.numeric(delta) && length(delta) == 1L && is.finite(delta) && delta > 0) {
    return(as.integer(delta))
  }
  NULL
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

.assemble_context_prompt <- function(prompt, context_reports, keep) {
  entries <- vapply(keep, function(i) {
    report <- context_reports[[i]]
    metadata <- report$metadata %||% list()
    row_index <- metadata$row_index %||% i
    source <- metadata$source %||% NA_character_
    source_label <- if (!is.na(source) && nzchar(source)) {
      paste0(" source=", source)
    } else {
      ""
    }
    paste(
      paste0("[context row=", row_index, source_label, "]"),
      report$text_clean,
      sep = "\n"
    )
  }, character(1))

  paste(
    prompt,
    "Context:",
    paste(c("---", entries), collapse = "\n\n---\n\n"),
    sep = "\n\n"
  )
}
