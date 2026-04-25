#' Guard a Local Ollama Chat
#'
#' Creates local Ollama chat clients through `ellmer::chat_ollama()` and runs
#' [secure_chat()] with a private reviewer workflow that stays on your machine.
#'
#' This is the easiest way to use `llmshieldr` with Ollama and `gemma3:4b`
#' without manually creating separate assistant and reviewer objects.
#'
#' @param prompt A single character string containing the user prompt.
#' @param policy A policy list from [policy_preset()]. Defaults to
#'   `enterprise_default` for a practical general-purpose setup.
#' @param context Optional character vector or data frame of context
#'   documents to append after scanning.
#' @param action Character. Override the scanner's recommended action. One of
#'   `"auto"`, `"redact"`, `"warn"`, or `"block"`.
#' @param checks Character. One of `"rules"`, `"llm"`, or `"both"`.
#' @param model Character. Ollama model for the user-facing assistant.
#' @param review_model Character. Ollama model for the reviewer. Defaults to
#'   `model`.
#'
#' @return A `secure_result` S3 object.
#'
#' @seealso [secure_chat()], [scan_prompt()], [llm_review()]
#'
#' @examples
#' \dontrun{
#' library(llmshieldr)
#'
#' # In a shell first: ollama pull gemma3:4b
#' result <- shield_ollama(
#'   prompt = "Explain this dplyr error and suggest a fix.",
#'   policy = policy_preset("enterprise_default"),
#'   checks = "both",
#'   model = "gemma3:4b"
#' )
#'
#' result$output
#' result$risk_summary
#' }
#'
#' @export
shield_ollama <- function(prompt,
                          policy = policy_preset("enterprise_default"),
                          context = NULL,
                          action = c("auto", "redact", "warn", "block"),
                          checks = c("rules", "llm", "both"),
                          model = "gemma3:4b",
                          review_model = model) {
  if (!requireNamespace("ellmer", quietly = TRUE)) {
    abort_missing_dependency("ellmer", "shield_ollama")
  }

  if (!rlang::is_string(model)) {
    abort_input_validation(
      arg = "model",
      expected = "a single character string",
      got = paste0("{.obj_type_friendly {model}}"),
      fn = "shield_ollama"
    )
  }

  if (!rlang::is_string(review_model)) {
    abort_input_validation(
      arg = "review_model",
      expected = "a single character string",
      got = paste0("{.obj_type_friendly {review_model}}"),
      fn = "shield_ollama"
    )
  }

  checks <- rlang::arg_match(checks)

  provider <- ellmer::chat_ollama(model = model)
  reviewer <- if (checks == "rules") {
    NULL
  } else {
    ellmer::chat_ollama(model = review_model)
  }

  secure_chat(
    prompt = prompt,
    provider = provider,
    policy = policy,
    context = context,
    action = action,
    reviewer = reviewer,
    checks = checks
  )
}
