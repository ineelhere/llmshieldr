#' Run a guarded chat call
#'
#' Orchestrates prompt scanning, optional context scanning, chat execution,
#' output scanning, rate guarding, and audit creation.
#'
#' @details
#' `secure_chat()` accepts any provider supported by `ellmer::chat()`. Set
#' `provider` to an ellmer provider name, optionally supply `model`, and pass
#' provider-specific constructor options through `provider_args`. It creates a
#' separate semantic-review chat when review is requested; that chat may use a
#' different provider, model, and argument list. You can instead supply an
#' existing `ellmer` chat object, another object with a `$chat()` method, or a
#' function through `chat`. Provider-created assistant chats are initialized
#' only after prompt and context checks permit a model call. A provider-created
#' semantic reviewer is initialized earlier when `checks` requires it. The
#' function executes these steps:
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
#' @param chat An existing `ellmer` chat object, an object with `$chat()`, or a
#'   function. Supply either `chat` or a provider name, not both.
#' @param policy A `shieldr_policy` or built-in policy name such as `"comprehensive"`.
#' @param reviewer Optional reviewer function or object with `$chat()`.
#' @param checks One of `"rules"`, `"nlp"`, `"llm"`, or `"both"`.
#' @param context Optional data frame of retrieved context.
#' @param context_authorize Optional function passed to [scan_context()] to
#'   authorize each retrieved row before it is included in the model prompt.
#' @param context_policy Optional provenance and authorization requirements from
#'   [context_policy()].
#' @param redaction Optional redaction strategy from [redaction_strategy()].
#' @param scanners Optional scanner configuration from [scanner_options()].
#' @param show_tokens Whether to attach token counts when `ellmer` is available.
#' @param audit_content `"metadata"` (default) omits prompt, output, finding
#'   excerpts and reviewer details from the audit. `"full"` retains them in
#'   memory; [write_audit_log()] requires a separate explicit opt-in to write
#'   them.
#' @param audit_key Optional secret key used for HMAC fingerprints in
#'   metadata-only audit findings. The key is never stored.
#' @param allowed_tools Explicit names of registered `ellmer` tools allowed
#'   during this call. The default empty vector denies tool-enabled chats before
#'   calling the model. Allowed calls are scanned before tool execution.
#' @param tool_policy Optional richer policy from [tool_policy()]. Its allowlist
#'   replaces `allowed_tools` and it adds schema, subject, spend, and loop limits.
#' @param tool_subject Optional authorization context passed to `tool_policy`.
#' @param output_contract Optional destination contract from [output_contract()].
#' @param grounding Optional citation policy from [grounding_policy()]. Citation
#'   IDs are checked against admitted context `document_id` values (or row IDs).
#' @param telemetry Optional privacy-safe event exporter from
#'   [telemetry_options()].
#' @param show_stats Show elapsed time, token use, network status, and
#'   transfer metrics when available.
#' @param provider Any provider name supported by `ellmer::chat()`, optionally
#'   in ellmer's `"provider/model"` form. `"gemini"` is accepted as an alias
#'   for `"google_gemini"`. An existing chat object passed as `provider` is
#'   still accepted as a legacy alias for `chat`.
#' @param model Optional assistant model name. Do not supply it when `provider`
#'   already contains a model. With Ollama, `NULL` discovers the first local
#'   model.
#' @param reviewer_model Model for the separate semantic reviewer, created only
#'   when `checks = "llm"` or `"both"` and `reviewer` is `NULL`. `NULL` uses the
#'   assistant provider and model.
#' @param provider_args Named list of additional arguments passed to
#'   `ellmer::chat()` and then to the selected assistant provider constructor.
#' @param reviewer_provider Optional ellmer provider name for the semantic
#'   reviewer. `NULL` uses the assistant provider.
#' @param reviewer_provider_args Named list of provider arguments for the
#'   reviewer. When the reviewer uses the assistant provider, `NULL` reuses
#'   `provider_args`; otherwise it passes no additional arguments. Use `list()`
#'   to explicitly pass none.
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
#' secure_chat("hello", provider = "ollama", model = model, checks = "rules")
#' secure_chat("hello", provider = "anthropic", checks = "rules")
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
                        context_authorize = NULL,
                        context_policy = NULL,
                        audit_content = c("metadata", "full"),
                        audit_key = NULL,
                        allowed_tools = character(),
                        tool_policy = NULL,
                        tool_subject = NULL,
                        output_contract = NULL,
                        grounding = NULL,
                        telemetry = NULL,
                        show_stats = FALSE,
                        provider = NULL,
                        model = NULL,
                        reviewer_model = NULL,
                        provider_args = list(),
                        reviewer_provider = NULL,
                        reviewer_provider_args = NULL,
                        ...) {
  stats <- .stats_begin(show_stats, "secure_chat")
  on.exit(.stats_end(stats), add = TRUE)
  .check_string(prompt, "prompt", allow_empty = TRUE)
  if (length(list(...)) > 0L) {
    cli::cli_abort("Unexpected arguments in {.arg ...}.")
  }
  if (!is.null(provider) && !is.character(provider) &&
      (is.function(provider) || .has_chat_method(provider))) {
    if (!is.null(chat)) cli::cli_abort("Use {.arg chat} only once.")
    chat <- provider
    provider <- NULL
  }
  if (is.null(provider)) {
    provider_options <- list(
      model = model,
      reviewer_model = reviewer_model,
      reviewer_provider = reviewer_provider,
      provider_args = if (length(provider_args) > 0L) provider_args else NULL,
      reviewer_provider_args = reviewer_provider_args
    )
    if (any(!vapply(provider_options, is.null, logical(1)))) {
      cli::cli_abort("Provider models, providers, and argument lists require {.arg provider}.")
    }
    chat <- .resolve_chat_arg(chat, list())
  } else {
    .check_string(provider, "provider")
    if (!is.null(model)) .check_string(model, "model")
    if (!is.null(reviewer_model)) .check_string(reviewer_model, "reviewer_model")
    if (!is.null(chat)) {
      cli::cli_abort("Supply either {.arg chat} or {.arg provider}, not both.")
    }
  }
  .validate_provider_args(provider_args, "provider_args")
  if (!is.null(reviewer_provider_args)) {
    .validate_provider_args(reviewer_provider_args, "reviewer_provider_args")
  }
  if (!is.null(reviewer_provider)) {
    .check_string(reviewer_provider, "reviewer_provider")
  }
  policy <- .as_policy(policy)
  checks <- .validate_checks(checks)
  redaction <- .validate_redaction_strategy(redaction)
  scanners <- .validate_scanner_options(scanners)
  show_tokens <- .validate_show_tokens(show_tokens)
  audit_content <- match.arg(audit_content)
  if (!is.null(audit_key)) .check_string(audit_key, "audit_key")
  if (!is.character(allowed_tools) || anyNA(allowed_tools)) {
    cli::cli_abort("{.arg allowed_tools} must be a character vector without missing values.")
  }
  .validate_tool_policy(tool_policy, allow_null = TRUE)
  .validate_context_policy(context_policy, allow_null = TRUE)
  .validate_output_contract(output_contract, allow_null = TRUE)
  .validate_grounding_policy(grounding, allow_null = TRUE)
  .validate_telemetry(telemetry, allow_null = TRUE)
  if (is.null(provider)) {
    .validate_chat(chat)
  } else if (is.null(reviewer) && checks %in% c("llm", "both")) {
    provider_chats <- .create_provider_chats(
      provider, model, reviewer_model, provider_args,
      reviewer_provider, reviewer_provider_args, checks,
      create_chat = FALSE,
      create_reviewer = TRUE
    )
    reviewer <- provider_chats$reviewer
  }
  .validate_reviewer_for_checks(reviewer, checks)
  .stats_track_reviewer(stats, reviewer, checks)
  if (!is.null(context) && !is.data.frame(context)) {
    cli::cli_abort("{.arg context} must be a data frame or {.code NULL}.")
  }
  if (!is.null(context_authorize) && !is.function(context_authorize)) {
    cli::cli_abort("{.arg context_authorize} must be a function or {.code NULL}.")
  }

  decision_id <- .decision_id()
  t0 <- proc.time()[["elapsed"]]
  prompt_started <- proc.time()[["elapsed"]]
  input_report <- scan_prompt(
    prompt,
    policy,
    reviewer = reviewer,
    checks = checks,
    redaction = redaction,
    scanners = scanners,
    show_tokens = show_tokens
  )
  prompt_ms <- .elapsed_ms(prompt_started)
  .emit_telemetry(telemetry, decision_id, "prompt", "completed", input_report, prompt_ms)

  if (identical(input_report$action, "block")) {
    .stats_text_tokens(stats, input_report$text_clean)
    final_action <- if (.reports_request_escalation(input_report)) {
      "escalate"
    } else {
      policy$controls$on_prompt_block
    }
    audit <- shieldr_audit(
      input_report = input_report,
      output_report = NULL,
      context_reports = NULL,
      prompt_clean = input_report$text_clean,
      output_raw = NULL,
      elapsed_ms = .elapsed_ms(t0),
      token_estimate = .count_tokens(input_report$text_clean),
      action = final_action,
      content_mode = audit_content,
      decision_id = decision_id,
      policy_version = policy$version,
      fingerprint_key = audit_key,
      metrics = .audit_metrics(
        total_ms = .elapsed_ms(t0), prompt_ms = prompt_ms,
        token_estimate = .count_tokens(input_report$text_clean),
        network_used = .reviewer_network_used(reviewer, checks),
        network_scope = .reviewer_network_scope(reviewer, checks),
        assistant_requests = 0L
      )
    )
    .emit_telemetry(telemetry, decision_id, "decision", "completed", input_report,
                    audit$elapsed_ms, list(final_action = final_action, assistant_requests = 0L))
    return(shieldr_result(
      output = .controlled_output(final_action, policy$controls),
      audit = audit,
      risk_summary = .risk_summary(input_report),
      action = final_action
    ))
  }

  context_reports <- NULL
  context_ms <- 0
  final_prompt <- input_report$text_clean
  if (!is.null(context)) {
    context_started <- proc.time()[["elapsed"]]
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
      show_tokens = show_tokens,
      authorize = context_authorize,
      context_policy = context_policy
    )
    context_ms <- .elapsed_ms(context_started)
    for (report in context_reports) {
      .emit_telemetry(
        telemetry, decision_id, "context", "completed", report,
        context_ms / max(length(context_reports), 1L),
        list(row_index = report$metadata$row_index, admission = report$metadata$admission)
      )
    }
    blocked_idx <- which(vapply(context_reports, function(report) report$action, character(1)) == "block")
    n_blocked <- length(blocked_idx)
    reviewer_escalation <- .reports_request_escalation(context_reports)
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
    if (reviewer_escalation || (n_blocked > 0L && policy$controls$on_context_block %in% c("block", "refuse", "escalate"))) {
      .stats_text_tokens(stats, input_report$text_clean)
      final_action <- if (reviewer_escalation) "escalate" else policy$controls$on_context_block
      audit <- shieldr_audit(
        input_report = input_report,
        output_report = NULL,
        context_reports = context_reports,
        prompt_clean = input_report$text_clean,
        output_raw = NULL,
        elapsed_ms = .elapsed_ms(t0),
        token_estimate = .count_tokens(input_report$text_clean),
        action = final_action,
        content_mode = audit_content,
        decision_id = decision_id,
        policy_version = policy$version,
        fingerprint_key = audit_key,
        metrics = .audit_metrics(
          total_ms = .elapsed_ms(t0), prompt_ms = prompt_ms,
          context_ms = context_ms,
          token_estimate = .count_tokens(input_report$text_clean),
          network_used = .reviewer_network_used(reviewer, checks),
          network_scope = .reviewer_network_scope(reviewer, checks),
          assistant_requests = 0L
        )
      )
      .emit_telemetry(telemetry, decision_id, "decision", "completed", NULL,
                      audit$elapsed_ms, list(final_action = final_action, assistant_requests = 0L))
      return(shieldr_result(
        output = .controlled_output(final_action, policy$controls),
        audit = audit,
        risk_summary = .risk_summary(input_report, context_reports),
        action = final_action
      ))
    }
    admitted_idx <- which(vapply(context_reports, function(report) {
      identical(report$metadata$admission %||% "admit", "admit")
    }, logical(1)))
    safe_idx <- if (identical(policy$controls$on_context_block, "keep_redacted")) {
      admitted_idx
    } else {
      admitted_idx[vapply(context_reports[admitted_idx], function(report) report$action != "block", logical(1))]
    }
    if (length(safe_idx) > 0L) {
      final_prompt <- .assemble_context_prompt(
        input_report$text_clean,
        context_reports = context_reports,
        keep = safe_idx
      )
    }
  }

  if (!is.null(provider)) {
    provider_chats <- .create_provider_chats(
      provider, model, reviewer_model, provider_args,
      reviewer_provider, reviewer_provider_args, checks,
      create_chat = TRUE,
      create_reviewer = FALSE
    )
    chat <- provider_chats$chat
    .validate_chat(chat)
  }

  tool_guard <- .guard_chat_tools(chat, allowed_tools, tool_policy, tool_subject,
                                  policy, reviewer, checks, redaction, scanners)
  on.exit(tool_guard$cleanup(), add = TRUE)

  strict_estimate <- 0
  reserved_tokens <- 0
  reserved_requests <- 0L
  if (!is.null(policy$rate_guard)) {
    strict_estimate <- if (isTRUE(policy$rate_guard$.strict)) .count_tokens(final_prompt) else 0
    output_reservation <- policy$rate_guard$.max_output_tokens %||% 0
    reserved_tokens <- strict_estimate + output_reservation
    policy$rate_guard$reserve(tokens = reserved_tokens, requests = 1L)
    reserved_requests <- 1L
  }

  chat_returned <- FALSE
  model_started <- proc.time()[["elapsed"]]
  chat_stage <- tryCatch(
    {
      .stats_network_from_chat(stats, chat)
      usage_before <- if (isTRUE(show_tokens) || isTRUE(show_stats)) .ellmer_usage_snapshot(chat) else NULL
      raw_output <- .with_elapsed_limit(
        function() .call_chat(chat, final_prompt),
        policy$rate_guard$.max_elapsed_seconds %||% NULL
      )
      chat_returned <- TRUE
      usage_after <- if (isTRUE(show_tokens) || isTRUE(show_stats)) .ellmer_usage_snapshot(chat) else NULL
      output_report <- scan_output(
        raw_output,
        policy,
        reviewer = reviewer,
        checks = checks,
        redaction = redaction,
        scanners = scanners,
        contract = output_contract,
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
      if (!is.null(policy$rate_guard) && !chat_returned &&
          (reserved_tokens > 0 || reserved_requests > 0L)) {
        policy$rate_guard$rollback(tokens = reserved_tokens, requests = reserved_requests)
      }
      stop(e)
    }
  )
  raw_output <- chat_stage$raw_output
  output_report <- chat_stage$output_report
  if (!is.null(policy$rate_guard$.max_output_tokens %||% NULL) &&
      .count_tokens(raw_output) > policy$rate_guard$.max_output_tokens) {
    output_report <- .add_output_limit_finding(output_report, policy)
  }
  model_and_output_ms <- .elapsed_ms(model_started)
  if (!is.null(grounding)) {
    admitted_reports <- Filter(function(report) {
      identical(report$metadata$admission %||% "admit", "admit") &&
        !identical(report$action, "block")
    }, context_reports %||% list())
    source_ids <- vapply(admitted_reports, function(report) {
      as.character(report$metadata$document_id %||% paste0("row-", report$metadata$row_index %||% "unknown"))
    }, character(1))
    grounding_report <- scan_grounding(output_report$text_clean, source_ids, grounding)
    output_report <- .merge_reports(output_report, grounding_report, policy)
  }
  .emit_telemetry(telemetry, decision_id, "output", "completed", output_report, model_and_output_ms)
  tool_reports <- tool_guard$reports()
  tool_action <- if (length(tool_reports) > 0L) {
    .combine_actions(vapply(tool_reports, function(report) report$action, character(1)))
  } else {
    "allow"
  }
  final_action <- .combine_actions(input_report$action, output_report$action, tool_action)
  if (identical(output_report$action, "block") || identical(tool_action, "block")) {
    final_action <- if (.reports_request_escalation(output_report, tool_reports)) {
      "escalate"
    } else {
      policy$controls$on_output_block
    }
  }

  token_estimate <- .ellmer_usage_delta(chat_stage$usage_before, chat_stage$usage_after) %||% .count_tokens(final_prompt, raw_output)
  if (!is.null(stats)) {
    stats$tokens <- token_estimate
    stats$token_source <- if (is.null(.ellmer_usage_delta(chat_stage$usage_before, chat_stage$usage_after))) "estimate" else "provider"
  }
  if (!is.null(policy$rate_guard)) {
    actual_delta <- token_estimate - reserved_tokens
    if (actual_delta > 0) {
      policy$rate_guard$update(tokens = actual_delta, requests = 0L)
    } else if (actual_delta < 0) {
      policy$rate_guard$rollback(tokens = -actual_delta, requests = 0L)
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
    action = final_action,
    content_mode = audit_content,
    tool_reports = tool_reports,
    decision_id = decision_id,
    policy_version = policy$version,
    fingerprint_key = audit_key,
    metrics = .audit_metrics(
      total_ms = .elapsed_ms(t0), prompt_ms = prompt_ms,
      context_ms = context_ms,
      model_and_output_ms = model_and_output_ms,
      token_estimate = token_estimate,
      network_used = .network_used(provider, chat),
      network_scope = .network_scope(provider, chat),
      assistant_requests = 1L,
      tool_calls = sum(vapply(tool_reports, function(report) {
        identical(report$metadata$stage, "tool_call")
      }, logical(1)))
    )
  )

  for (report in tool_reports) {
    .emit_telemetry(telemetry, decision_id, report$metadata$stage %||% "tool", "completed", report)
  }
  .emit_telemetry(telemetry, decision_id, "decision", "completed", output_report,
                  audit$elapsed_ms, list(final_action = final_action, assistant_requests = 1L))

  shieldr_result(
    output = if (final_action %in% c("block", "escalate")) NULL else .controlled_output(final_action, policy$controls) %||% output_report$text_clean,
    audit = audit,
    risk_summary = .risk_summary(input_report, output_report, context_reports, tool_reports),
    action = final_action
  )
}

.guard_chat_tools <- function(chat, allowed_tools, tool_policy, tool_subject,
                              policy, reviewer, checks, redaction, scanners) {
  no_cleanup <- function() invisible(NULL)
  no_guard <- list(cleanup = no_cleanup, reports = function() list())
  if (is.function(chat) || !is.function(tryCatch(chat$get_tools, error = function(e) NULL))) {
    return(no_guard)
  }
  registered <- chat$get_tools()
  if (length(registered) == 0L) {
    return(no_guard)
  }
  effective_policy <- .as_tool_policy(tool_policy, allowed_tools)
  if (!is.null(policy$rate_guard$.max_tool_calls %||% NULL)) {
    effective_policy$max_calls <- min(effective_policy$max_calls, policy$rate_guard$.max_tool_calls)
  }
  if (length(effective_policy$allowed_tools) == 0L) {
    cli::cli_abort("Chat has registered tools. Supply {.arg allowed_tools} explicitly before calling the model.")
  }
  if (!is.function(tryCatch(chat$on_tool_request, error = function(e) NULL)) ||
      !is.function(tryCatch(chat$on_tool_result, error = function(e) NULL))) {
    cli::cli_abort("Tool-enabled chat must support {.code on_tool_request()} and {.code on_tool_result()} hooks.")
  }
  state <- new.env(parent = emptyenv())
  state$reports <- list()
  state$limits <- .tool_policy_state()
  remove_request <- chat$on_tool_request(function(request) {
    name <- .tool_event_field(request, "name")
    args <- .tool_event_field(request, "arguments")
    if (!is.character(name) || length(name) != 1L || is.na(name)) {
      cli::cli_abort("Tool request has no valid name; execution denied.")
    }
    report <- scan_tool_call(name, args, allowed_tools = effective_policy$allowed_tools,
                             tool_policy = effective_policy, subject = tool_subject,
                             state = state$limits,
                             policy = policy, reviewer = reviewer, checks = checks,
                             redaction = redaction, scanners = scanners)
    state$reports[[length(state$reports) + 1L]] <- report
    if (!identical(report$action, "allow")) {
      if (requireNamespace("ellmer", quietly = TRUE) &&
          exists("tool_reject", envir = asNamespace("ellmer"), mode = "function")) {
        ellmer::tool_reject("Blocked by llmshieldr tool policy.")
      }
      cli::cli_abort("Tool request blocked by llmshieldr before execution.")
    }
  })
  remove_result <- tryCatch(chat$on_tool_result(function(result) {
    request <- .tool_event_field(result, "request")
    name <- .tool_event_field(request, "name")
    value <- .tool_event_field(result, "value")
    tool_error <- .tool_event_field(result, "error")
    if (!is.null(tool_error)) {
      error_text <- if (inherits(tool_error, "condition")) {
        conditionMessage(tool_error)
      } else {
        .tool_output_text(tool_error)
      }
      value <- paste(.tool_output_text(value), error_text, sep = "\n")
    }
    if (!is.character(name) || length(name) != 1L || is.na(name)) {
      cli::cli_abort("Tool result has no valid request name; release denied.")
    }
    report <- scan_tool_output(name, value, policy = policy, reviewer = reviewer,
                               checks = checks, redaction = redaction,
                               scanners = scanners)
    state$reports[[length(state$reports) + 1L]] <- report
    if (!identical(report$action, "allow")) {
      cli::cli_abort("Tool output blocked before the next model request.")
    }
  }), error = function(e) {
    if (is.function(remove_request)) remove_request()
    stop(e)
  })
  list(
    cleanup = function() {
      if (is.function(remove_result)) remove_result()
      if (is.function(remove_request)) remove_request()
      invisible(NULL)
    },
    reports = function() state$reports
  )
}

.create_provider_chats <- function(provider, model, reviewer_model,
                                   provider_args, reviewer_provider,
                                   reviewer_provider_args, checks,
                                   create_chat = TRUE,
                                   create_reviewer = TRUE) {
  needs_reviewer <- isTRUE(create_reviewer) && checks %in% c("llm", "both")
  assistant_name <- .ellmer_chat_name(provider, model, "model")
  if (is.null(reviewer_provider_args)) {
    same_provider <- is.null(reviewer_provider) || identical(
      .ellmer_provider(.normalize_ellmer_provider(reviewer_provider)),
      .ellmer_provider(assistant_name)
    )
    reviewer_provider_args <- if (same_provider) {
      provider_args
    } else {
      list()
    }
  }
  reviewer_name <- NULL
  if (needs_reviewer) {
    if (is.null(reviewer_provider) && is.null(reviewer_model)) {
      reviewer_name <- assistant_name
    } else {
      reviewer_provider <- reviewer_provider %||% .ellmer_provider(assistant_name)
      reviewer_name <- .ellmer_chat_name(
        reviewer_provider, reviewer_model, "reviewer_model"
      )
    }
  }
  list(
    chat = if (isTRUE(create_chat)) {
      .call_ellmer_chat(assistant_name, provider_args)
    } else NULL,
    reviewer = if (needs_reviewer) {
      .call_ellmer_chat(reviewer_name, reviewer_provider_args)
    } else NULL
  )
}

.ellmer_chat_name <- function(provider, model = NULL, model_arg = "model") {
  .check_string(provider, "provider")
  provider <- .normalize_ellmer_provider(provider)
  if (!is.null(model)) {
    .check_string(model, model_arg)
    if (grepl("/", provider, fixed = TRUE)) {
      cli::cli_abort(
        "{.arg provider} already contains a model; do not also supply {.arg {model_arg}}."
      )
    }
    provider <- paste0(provider, "/", model)
  }
  if (identical(provider, "ollama")) {
    provider <- paste0("ollama/", .resolve_ollama_model())
  }
  provider
}

.normalize_ellmer_provider <- function(provider) {
  sub("^gemini(?=/|$)", "google_gemini", provider, perl = TRUE)
}

.ellmer_provider <- function(name) {
  strsplit(name, "/", fixed = TRUE)[[1L]][[1L]]
}

.validate_provider_args <- function(x, arg) {
  if (!is.list(x)) {
    cli::cli_abort("{.arg {arg}} must be a named list.")
  }
  if (length(x) == 0L) return(invisible(TRUE))
  nms <- names(x)
  if (is.null(nms) || any(!nzchar(nms)) || anyDuplicated(nms)) {
    cli::cli_abort("{.arg {arg}} must have unique, non-empty names.")
  }
  reserved <- intersect(nms, c("name", "model"))
  if (length(reserved) > 0L) {
    cli::cli_abort(
      "{.arg {arg}} cannot contain reserved entries: {.field {reserved}}."
    )
  }
  invisible(TRUE)
}

.call_ellmer_chat <- function(name, args = list()) {
  rlang::check_installed("ellmer", version = "0.3.0")
  if (!"echo" %in% names(args)) args$echo <- "none"
  do.call(ellmer::chat, c(list(name = name), args))
}

.tool_event_field <- function(x, field) {
  if (requireNamespace("S7", quietly = TRUE)) {
    value <- tryCatch(S7::prop(x, field), error = function(e) NULL)
    if (!is.null(value)) return(value)
  }
  if (base::isS4(x) && field %in% methods::slotNames(x)) {
    return(methods::slot(x, field))
  }
  if (is.list(x)) return(x[[field]])
  NULL
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

.ellmer_usage_snapshot <- function(chat = NULL) {
  if (!is.null(chat) && !is.function(chat) &&
      is.function(tryCatch(chat$get_tokens, error = function(e) NULL))) {
    usage <- tryCatch(chat$get_tokens(), error = function(e) NULL)
    if (is.data.frame(usage)) return(usage)
  }
  NULL
}

.add_output_limit_finding <- function(report, policy) {
  finding <- .synthetic_finding(
    "llm06.output.token_limit", "llm06", "critical",
    "Model output exceeds the configured maximum output token estimate.",
    action = "block"
  )
  report$findings <- .dedupe_findings(c(report$findings, list(finding)))
  report$risk_score <- .score_findings(report$findings)
  report$action <- .resolve_action(report$risk_score, report$findings, .output_policy(policy))
  report
}

.ellmer_usage_delta <- function(before, after) {
  if (!is.data.frame(after)) {
    return(NULL)
  }
  token_cols <- intersect(c("input", "output"), names(after))
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

.reports_request_escalation <- function(...) {
  reports <- .collect_reports(list(...))
  any(vapply(reports, function(report) {
    identical(report$metadata$reviewer_failure_action %||% NULL, "escalate")
  }, logical(1)))
}

.audit_metrics <- function(...) {
  values <- list(...)
  c(
    list(
      schema_version = "1.0",
      upload_bytes = NA_real_,
      download_bytes = NA_real_,
      upload_rate_bytes_s = NA_real_,
      download_rate_bytes_s = NA_real_,
      retry_count = NA_integer_
    ),
    values
  )
}

.network_scope <- function(provider = NULL, chat = NULL) {
  if (!is.null(provider)) {
    provider_name <- .ellmer_provider(.normalize_ellmer_provider(provider))
    return(if (identical(provider_name, "ollama")) "loopback" else "external")
  }
  if (is.function(chat)) {
    scope <- attr(chat, "llmshieldr_network_scope", exact = TRUE)
    if (!is.null(scope)) return(as.character(scope)[[1L]])
    used <- attr(chat, "llmshieldr_network", exact = TRUE)
    if (identical(used, "no")) return("none")
    return("unknown")
  }
  provider_value <- tryCatch(chat$get_provider(), error = function(e) NULL)
  provider_text <- .provider_identity_text(provider_value)
  if (grepl("ollama|localhost|127\\.0\\.0\\.1", provider_text)) "loopback" else if (nzchar(provider_text)) "external" else "unknown"
}

.provider_identity_text <- function(provider) {
  if (is.null(provider)) {
    return("")
  }

  candidates <- list(
    if (is.character(provider)) provider else NULL,
    tryCatch(provider[["name"]], error = function(e) NULL),
    tryCatch(provider[["base_url"]], error = function(e) NULL),
    tryCatch(provider@name, error = function(e) NULL),
    tryCatch(provider@base_url, error = function(e) NULL),
    attr(provider, "name", exact = TRUE),
    attr(provider, "base_url", exact = TRUE),
    class(provider)
  )
  parts <- unlist(lapply(candidates, function(value) {
    if (is.character(value)) {
      return(value)
    }
    if (is.atomic(value)) {
      return(tryCatch(as.character(value), error = function(e) character()))
    }
    character()
  }), use.names = FALSE)
  parts <- parts[!is.na(parts) & nzchar(parts)]
  tolower(paste(parts, collapse = " "))
}

.network_used <- function(provider = NULL, chat = NULL) {
  scope <- .network_scope(provider, chat)
  if (identical(scope, "none")) FALSE else if (identical(scope, "unknown")) NA else TRUE
}

.reviewer_network_scope <- function(reviewer, checks) {
  if (!checks %in% c("llm", "both") || is.null(reviewer)) return("none")
  .network_scope(NULL, reviewer)
}

.reviewer_network_used <- function(reviewer, checks) {
  scope <- .reviewer_network_scope(reviewer, checks)
  if (identical(scope, "none")) FALSE else if (identical(scope, "unknown")) NA else TRUE
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
