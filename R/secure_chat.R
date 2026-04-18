#' Secure chat wrapper
#'
#' @param prompt Character string
#' @param provider LLM provider
#' @param policy Policy list
#' @param action Action to take
#' @return secure_result object
#' @export
secure_chat <- function(prompt, provider, policy, action = "redact") {
  # Preflight
  input_report <- scan_prompt(prompt, policy)
  if (input_report$action == "block") {
    stop("Blocked by policy")
  }
  # Redact if needed
  clean_prompt <- if (action == "redact") input_report$text_clean else prompt
  # Call provider (placeholder for ellmer)
  # Assuming provider is an ellmer chat object, e.g., chat <- chat_openai(model = "gpt-4")
  # output <- chat$chat(clean_prompt)
  output <- paste("Response to:", clean_prompt)  # placeholder
  # Postflight
  output_report <- scan_output(output)
  # Audit
  audit <- structure(list(
    timestamp = Sys.time(),
    policy = policy$name,
    model = "gpt-4",  # placeholder
    provider = "openai",  # placeholder
    input_report = input_report,
    output_report = output_report,
    final_action = action,
    redactions = list()  # placeholder
  ), class = "shield_audit")
  # Return
  structure(list(
    output = output,
    audit = audit,
    risk_summary = tibble::tibble(score = input_report$score, band = input_report$band, rules_triggered = length(input_report$findings), action_taken = action)
  ), class = "secure_result")
}