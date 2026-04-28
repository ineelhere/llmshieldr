#' Guard an Ollama chat workflow
#'
#' Convenience wrapper that creates separate `ellmer` Ollama sessions for the
#' assistant and semantic reviewer, then delegates to [secure_chat()].
#'
#' @details
#' This is an optional local-model path. It requires the suggested `ellmer`
#' package and a running Ollama installation. Two chat sessions are created:
#' one for the assistant response and one for reviewer checks. Keeping them
#' separate avoids mixing safety-review instructions into the assistant's
#' conversation state.
#'
#' For hosted or custom providers, use [secure_chat()] directly.
#'
#' @param prompt User prompt.
#' @param policy A `shieldr_policy`.
#' @param checks One of `"rules"`, `"llm"`, or `"both"`.
#' @param model Ollama model name.
#' @param context Optional data frame of retrieved context.
#'
#' @return A `shieldr_result`.
#' @examples
#' \dontrun{
#' shield_ollama("Summarise this safely.", policy_preset("enterprise_default"))
#' }
#' @export
shield_ollama <- function(prompt,
                          policy,
                          checks = "both",
                          model = "gemma3:4b",
                          context = NULL) {
  rlang::check_installed("ellmer")
  .check_string(model, "model")
  assistant <- ellmer::chat_ollama(model = model)
  reviewer <- ellmer::chat_ollama(model = model)
  secure_chat(prompt, assistant, policy, reviewer = reviewer, checks = checks, context = context)
}
