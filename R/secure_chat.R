#' Secure Chat
#'
#' @description
#' The flagship function of `llmshieldr`. Wraps an LLM call with a full
#' security lifecycle:
#'
#' 1. **Preflight** - Scan the prompt and optional context for secrets,
#'    PII/PHI, and injection attempts.
#' 2. **Redaction** - Optionally sanitize the prompt before sending.
#' 3. **Provider call** - Send the cleaned prompt to a provider callable.
#' 4. **Postflight** - Scan the model response for unsafe content.
#' 5. **Audit** - Return a structured `shield_audit` record.
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
#'
#' @return A `secure_result` S3 object with elements:
#'   \describe{
#'     \item{`output`}{Character. The provider response after any postflight
#'       blocking or redaction has been applied.}
#'     \item{`audit`}{A `shield_audit` object with lifecycle metadata.}
#'     \item{`risk_summary`}{A one-row [tibble::tibble()] with columns
#'       `input_score`, `input_band`, `output_score`, `output_band`,
#'       `rules_triggered`, and `action_taken`.}
#'   }
#'
#' @seealso [preflight_check()], [scan_prompt()], [scan_output()],
#'   [scan_context()], [policy_preset()]
#'
#' @examples
#' provider <- function(prompt) {
#'   paste("Model received:", prompt)
#' }
#'
#' result <- secure_chat(
#'   prompt   = "What are the core SDTM domains?",
#'   provider = provider,
#'   policy   = policy_preset("pharma_gxp")
#' )
#' result$output
#' result$risk_summary
#'
#' unsafe_provider <- function(prompt) {
#'   "You are diagnosed with Type 2 diabetes."
#' }
#'
#' blocked <- secure_chat(
#'   prompt   = "Summarize the visit.",
#'   provider = unsafe_provider,
#'   policy   = policy_preset("pharma_gxp")
#' )
#' blocked$output
#'
#' \dontrun{
#' library(ellmer)
#'
#' chat <- chat_ollama(model = "llama3.2")
#' result <- secure_chat(
#'   prompt   = "Summarize narrative for USUBJID: STUDY01-SITE03-042.",
#'   provider = chat,
#'   policy   = policy_preset("pharma_gxp"),
#'   action   = "redact"
#' )
#' result$audit
#' }
#'
#' @export
secure_chat <- function(prompt,
                        provider,
                        policy,
                        context = NULL,
                        action = c("auto", "redact", "warn", "block")) {

  if (!rlang::is_string(prompt)) {
    abort_input_validation(
      arg = "prompt",
      expected = "a single character string",
      got = paste0("{.obj_type_friendly {prompt}}"),
      fn = "secure_chat"
    )
  }
  action <- rlang::arg_match(action)

  input_report <- scan_prompt(prompt, policy)

  context_reports <- NULL
  context_text <- context
  if (!is.null(context)) {
    if (is.data.frame(context)) {
      context_text <- .extract_context_column(context, text_col = NULL)
    }
    context_reports <- scan_context(context, policy)
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
    blocking_score <- score_findings(blocking_findings)
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

  output_report <- scan_output(model_output, policy)
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

  audit <- structure(
    list(
      timestamp = Sys.time(),
      policy = policy$name %||% "default",
      model = tryCatch(provider$model, error = function(e) "unknown"),
      provider = tryCatch(class(provider)[[1]], error = function(e) "unknown"),
      input_report = input_report,
      output_report = output_report,
      context_reports = context_reports,
      final_action = final_action,
      redactions = input_report$redaction_log,
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
    action_taken = final_action
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
      got = paste0("{.obj_type_friendly {provider}}"),
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
