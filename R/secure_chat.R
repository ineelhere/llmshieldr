#' Secure Chat
#'
#' @description
#' Wraps an LLM call with a full safety lifecycle:
#'
#' 1. Preflight checks on the prompt and optional context.
#' 2. Optional redaction before the provider call.
#' 3. Provider execution.
#' 4. Postflight checks on the model response.
#' 5. A structured audit record you can inspect or persist.
#'
#' You can keep the checks fully rule-based, ask a local reviewer model to
#' inspect the text, or combine both approaches.
#'
#' @param prompt A single character string containing the user prompt.
#' @param provider A provider callable. This can be an `ellmer` chat object
#'   with a `chat()` method, or a plain function that accepts one prompt
#'   string and returns one character response.
#' @param policy A policy list from [policy_preset()]. Controls the active
#'   rules and the action thresholds.
#' @param context An optional character vector or data frame of context
#'   documents. Data frames are scanned via their first character column.
#'   Context is scanned separately with [scan_context()] before being appended
#'   to the prompt.
#' @param action Character. Override the scanner's recommended action. One of
#'   `"auto"`, `"redact"`, `"warn"`, or `"block"`.
#' @param reviewer Optional reviewer callable used when `checks` is `"llm"`
#'   or `"both"`. Use a separate reviewer object from `provider` so the
#'   review conversation does not mix with the user-facing chat state.
#' @param checks Character. One of `"rules"`, `"llm"`, or `"both"`.
#'
#' @return A `secure_result` S3 object with elements:
#'   \describe{
#'     \item{`output`}{Character. The provider response after any postflight
#'       blocking or redaction has been applied.}
#'     \item{`audit`}{A `shield_audit` object with lifecycle metadata.}
#'     \item{`risk_summary`}{A one-row [tibble::tibble()] with columns
#'       `input_score`, `input_band`, `output_score`, `output_band`,
#'       `rules_triggered`, `action_taken`, and `checks_used`.}
#'   }
#'
#' @seealso [preflight_check()], [scan_prompt()], [scan_output()],
#'   [scan_context()], [policy_preset()], [shield_ollama()]
#'
#' @examples
#' provider <- function(prompt) {
#'   paste("Model received:", prompt)
#' }
#'
#' result <- secure_chat(
#'   prompt = "What are the core SDTM domains?",
#'   provider = provider,
#'   policy = policy_preset("pharma_gxp")
#' )
#' result$output
#' result$risk_summary
#'
#' unsafe_provider <- function(prompt) {
#'   "You are diagnosed with Type 2 diabetes."
#' }
#'
#' blocked <- secure_chat(
#'   prompt = "Summarize the visit.",
#'   provider = unsafe_provider,
#'   policy = policy_preset("pharma_gxp")
#' )
#' blocked$output
#'
#' \dontrun{
#' library(ellmer)
#'
#' assistant <- chat_ollama(model = "gemma3:4b")
#' reviewer <- chat_ollama(model = "gemma3:4b")
#'
#' result <- secure_chat(
#'   prompt = "Summarize narrative for USUBJID: STUDY01-SITE03-042.",
#'   provider = assistant,
#'   reviewer = reviewer,
#'   policy = policy_preset("pharma_gxp"),
#'   action = "redact",
#'   checks = "both"
#' )
#' result$audit
#' }
#'
#' @export
secure_chat <- function(prompt,
                        provider,
                        policy,
                        context = NULL,
                        action = c("auto", "redact", "warn", "block"),
                        reviewer = NULL,
                        checks = c("rules", "llm", "both")) {
  if (!rlang::is_string(prompt)) {
    abort_input_validation(
      arg = "prompt",
      expected = "a single character string",
      got = "{.obj_type_friendly {prompt}}",
      fn = "secure_chat"
    )
  }

  action <- rlang::arg_match(action)
  checks <- rlang::arg_match(checks)

  input_report <- scan_prompt(
    text = prompt,
    policy = policy,
    reviewer = reviewer,
    checks = checks
  )

  context_reports <- NULL
  context_text <- context
  if (!is.null(context)) {
    if (is.data.frame(context)) {
      context_text <- .extract_context_column(context, text_col = NULL)
    }

    context_reports <- scan_context(
      text = context,
      policy = policy,
      reviewer = reviewer,
      checks = checks
    )
  }

  effective_action <- if (action == "auto") {
    input_report$action
  } else {
    action
  }

  if (!is.null(context_reports)) {
    context_actions <- vapply(context_reports, `[[`, character(1), "action")
    effective_action <- .strongest_action(c(effective_action, context_actions))
  }

  if (effective_action == "block") {
    blocking_findings <- input_report$findings
    if (!is.null(context_reports)) {
      context_findings <- unlist(
        lapply(context_reports, `[[`, "findings"),
        recursive = FALSE
      )
      blocking_findings <- c(blocking_findings, context_findings)
    }

    blocking_score <- if (length(blocking_findings) == 0L) {
      input_report$score
    } else {
      score_findings(blocking_findings)
    }
    blocking_band <- get_band(blocking_score)

    abort_policy_block(
      policy_name = policy$name %||% "default",
      findings = blocking_findings,
      score = blocking_score,
      band = blocking_band,
      block_threshold = policy$thresholds$block %||% 100
    )
  }

  if (effective_action == "warn") {
    cli::cli_warn(
      "Prompt findings triggered a {.val warn} action. Review the audit before downstream use."
    )
  }

  send_prompt <- if (effective_action == "redact") {
    input_report$text_clean
  } else {
    prompt
  }

  if (!is.null(context_text) && effective_action == "redact") {
    clean_context <- vapply(context_reports, `[[`, character(1), "text_clean")
    full_prompt <- paste(
      c(send_prompt, "", "--- Context ---", clean_context),
      collapse = "\n"
    )
  } else if (!is.null(context_text)) {
    full_prompt <- paste(
      c(send_prompt, "", "--- Context ---", context_text),
      collapse = "\n"
    )
  } else {
    full_prompt <- send_prompt
  }

  model_output <- tryCatch(
    .call_provider(provider, full_prompt),
    error = function(e) {
      abort_provider_failure(provider_msg = conditionMessage(e))
    }
  )

  output_report <- scan_output(
    text = model_output,
    policy = policy,
    reviewer = reviewer,
    checks = checks
  )

  final_action <- .strongest_action(c(effective_action, output_report$action))

  returned_output <- if (output_report$action == "block") {
    "[BLOCKED_OUTPUT]"
  } else if (output_report$action == "redact") {
    output_report$text_clean
  } else {
    model_output
  }

  if (output_report$action == "warn") {
    cli::cli_warn(
      "Output findings triggered a {.val warn} action. Review the audit before downstream use."
    )
  }

  all_redactions <- c(
    input_report$redaction_log,
    output_report$redaction_log
  )
  if (!is.null(context_reports)) {
    context_redactions <- unlist(
      lapply(context_reports, `[[`, "redaction_log"),
      recursive = FALSE
    )
    all_redactions <- c(all_redactions, context_redactions)
  }

  audit <- structure(
    list(
      timestamp = Sys.time(),
      policy = policy$name %||% "default",
      model = .provider_model(provider),
      provider = .provider_name(provider),
      reviewer_model = .provider_model(reviewer),
      reviewer_provider = .provider_name(reviewer),
      checks = checks,
      input_report = input_report,
      output_report = output_report,
      context_reports = context_reports,
      final_action = final_action,
      redactions = all_redactions,
      prompt_sent = full_prompt
    ),
    class = "shield_audit"
  )

  risk_summary <- tibble::tibble(
    input_score = input_report$score,
    input_band = input_report$band,
    output_score = output_report$score,
    output_band = output_report$band,
    rules_triggered = length(input_report$findings) + length(output_report$findings),
    action_taken = final_action,
    checks_used = checks
  )

  structure(
    list(
      output = returned_output,
      audit = audit,
      risk_summary = risk_summary
    ),
    class = "secure_result"
  )
}


#' @noRd
#' @keywords internal
.call_provider <- function(provider, prompt) {
  chat_method <- NULL
  if (is.environment(provider) || is.list(provider)) {
    chat_method <- provider$chat
  }

  if (is.function(provider)) {
    response <- provider(prompt)
  } else if (!is.null(chat_method) && is.function(chat_method)) {
    response <- chat_method(prompt)
  } else {
    abort_input_validation(
      arg = "provider",
      expected = "a function or object with a `chat()` method",
      got = "{.obj_type_friendly {provider}}",
      fn = "secure_chat"
    )
  }

  if (!rlang::is_string(response)) {
    abort_provider_failure(
      provider_msg = "Provider responses must be a single character string."
    )
  }

  response
}


#' @noRd
#' @keywords internal
.provider_model <- function(provider) {
  if (is.null(provider)) {
    return(NA_character_)
  }

  tryCatch(provider$model %||% "unknown", error = function(e) "unknown")
}


#' @noRd
#' @keywords internal
.provider_name <- function(provider) {
  if (is.null(provider)) {
    return(NA_character_)
  }

  tryCatch(class(provider)[[1]] %||% "unknown", error = function(e) "unknown")
}
