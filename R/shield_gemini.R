#' Guard a Gemini Developer API chat workflow (deprecated)
#'
#' This compatibility wrapper delegates to [secure_chat()] with
#' `provider = "gemini"`. New code should use that common provider path.
#' It requires the suggested `ellmer` package and `GEMINI_API_KEY` or
#' `GOOGLE_API_KEY` in the environment. No request is made until this function
#' is called.
#'
#' @details
#' The default model names had a free tier when this package was documented;
#' availability, quotas, and data terms can change. Check
#' <https://ai.google.dev/gemini-api/docs/pricing> and
#' <https://ai.google.dev/gemini-api/docs/rate-limits> for your project.
#' Gemini requests transmit the cleaned prompt and admitted context to Google.
#' The Gemini API free tier may use submitted content to improve Google products;
#' avoid sending sensitive data unless your organization permits it.
#'
#' @param prompt User prompt.
#' @param policy A `shieldr_policy` or built-in policy name.
#' @param checks One of `"rules"`, `"nlp"`, `"llm"`, or `"both"`.
#' @param model Explicit Gemini assistant model name.
#' @param reviewer_model Explicit Gemini semantic reviewer model name.
#' @param context Optional data frame of retrieved context.
#' @param context_authorize Optional row authorization function.
#' @param redaction Optional redaction strategy.
#' @param scanners Optional scanner configuration.
#' @param show_tokens Whether to attach token counts.
#' @param show_stats Show execution statistics as messages.
#' @param audit_content `"metadata"` (default) or `"full"`.
#'
#' @return A `shieldr_result`.
#' @examples
#' \dontrun{
#' # Set GEMINI_API_KEY in your environment before running.
#' result <- shield_gemini("Summarize this public note.", show_stats = TRUE)
#' result$output
#' }
#' @export
shield_gemini <- function(prompt,
                          policy = "enterprise_default",
                          checks = "both",
                          model = "gemini-2.5-flash",
                          reviewer_model = "gemini-2.5-flash-lite",
                          context = NULL,
                          context_authorize = NULL,
                          redaction = NULL,
                          scanners = scanner_options(),
                          show_tokens = FALSE,
                          show_stats = FALSE,
                          audit_content = c("metadata", "full")) {
  .Deprecated("secure_chat", package = "llmshieldr")
  secure_chat(
    prompt = prompt, provider = "gemini", policy = policy, checks = checks,
    model = model, reviewer_model = reviewer_model,
    context = context, context_authorize = context_authorize,
    redaction = redaction, scanners = scanners, show_tokens = show_tokens,
    show_stats = show_stats, audit_content = audit_content
  )
}
