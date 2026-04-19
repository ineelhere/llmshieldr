#' Scan LLM Output for Unsafe Content
#'
#' Inspects model-generated text for prohibited patterns: unsupported efficacy
#' or safety claims, unauthorised diagnosis or prescribing language,
#' unreviewed label language, autonomous action claims, and domain-specific
#' violations (financial advice, legal opinions).
#'
#' @param text A single character string — the LLM's response text.
#' @param policy A policy list (from [policy_preset()]). When `NULL`, all
#'   output-type rules from the active rule bank are used.
#'
#' @return A `scan_report` S3 object with the same structure as
#'   [scan_prompt()], scoped to output-specific rules.
#'
#' @seealso [scan_prompt()], [secure_chat()]
#'
#' @examples
#' # Clean output — passes
#' report <- scan_output("The AE domain captures adverse event data.")
#' report$passed
#'
#' # Unsupported efficacy claim flagged
#' report <- scan_output("This drug significantly reduced mortality by 50%.")
#' report$passed
#' report$findings[[1]]$description
#' report$action
#'
#' # Diagnosis language blocked
#' report <- scan_output("You are diagnosed with Type 2 diabetes.")
#' report$action
#'
#' # Autonomous action flagged
#' report <- scan_output("I will now execute the deletion of all records.")
#' report$findings[[1]]$owasp
#'
#' @export
scan_output <- function(text, policy = NULL) {
  if (!rlang::is_string(text)) {
    abort_input_validation(
      arg      = "text",
      expected = "a single character string",
      got      = paste0("{.obj_type_friendly {text}}"),
      fn       = "scan_output"
    )
  }

  if (is.null(policy)) {
    active_rules <- get_active_rules()
  } else {
    active_rules <- policy$rules %||% get_active_rules()
  }

  # Filter to output-type rules only
  output_rules <- purrr::keep(active_rules, ~ .x$type == "output")

  findings <- purrr::keep(output_rules, function(rule) {
    stringr::str_detect(text, stringr::regex(rule$pattern, ignore_case = TRUE))
  })

  score  <- score_findings(findings)
  band   <- get_band(score)
  action <- decide_action(score, policy)

  redaction <- redact_text(text, findings)

  structure(
    list(
      passed        = length(findings) == 0L,
      score         = score,
      band          = band,
      findings      = findings,
      action        = action,
      text_original = text,
      text_clean    = redaction$text,
      redaction_log = redaction$redaction_log
    ),
    class = "scan_report"
  )
}