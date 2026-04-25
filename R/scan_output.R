#' Scan LLM Output for Unsafe Content
#'
#' Runs output checks with rule-based detectors, a reviewer LLM, or both.
#' This is useful when you want to inspect generated text before showing it
#' to users, writing it into a report, or handing it to downstream code.
#'
#' @param text A single character string containing the model response.
#' @param policy A policy list (from [policy_preset()]). When `NULL`, all
#'   output-type rules from the active rule bank are used.
#' @param reviewer Optional reviewer callable used when `checks` is `"llm"`
#'   or `"both"`. This can be an `ellmer` chat object with a `chat()`
#'   method, or a plain function that returns one JSON string.
#' @param checks Character. One of `"rules"`, `"llm"`, or `"both"`.
#'
#' @return A `scan_report` S3 object with the same structure as
#'   [scan_prompt()], scoped to output-specific rules.
#'
#' @seealso [scan_prompt()], [secure_chat()], [llm_review()]
#'
#' @examples
#' report <- scan_output("The AE domain captures adverse event data.")
#' report$passed
#'
#' report <- scan_output("This drug significantly reduced mortality by 50%.")
#' report$findings[[1]]$description
#' report$action
#'
#' report <- scan_output("You are diagnosed with Type 2 diabetes.")
#' report$action
#'
#' report <- scan_output("I will now execute the deletion of all records.")
#' report$findings[[1]]$owasp
#'
#' \dontrun{
#' library(ellmer)
#'
#' reviewer <- chat_ollama(model = "gemma3:4b")
#' report <- scan_output(
#'   text = "You should take this medication immediately.",
#'   policy = policy_preset("pharma_gxp"),
#'   reviewer = reviewer,
#'   checks = "both"
#' )
#' report
#' }
#'
#' @export
scan_output <- function(text,
                        policy = NULL,
                        reviewer = NULL,
                        checks = c("rules", "llm", "both")) {
  if (!rlang::is_string(text)) {
    abort_input_validation(
      arg = "text",
      expected = "a single character string",
      got = paste0("{.obj_type_friendly {text}}"),
      fn = "scan_output"
    )
  }

  checks <- rlang::arg_match(checks)

  rule_report <- if (checks %in% c("rules", "both")) {
    .scan_output_rules(text, policy = policy)
  } else {
    NULL
  }

  llm_report <- if (checks %in% c("llm", "both")) {
    llm_review(
      text = text,
      reviewer = reviewer,
      text_type = "output",
      policy = policy
    )
  } else {
    NULL
  }

  .combine_scan_reports(
    text = text,
    rule_report = rule_report,
    llm_report = llm_report,
    checks = checks
  )
}


#' @noRd
#' @keywords internal
.scan_output_rules <- function(text, policy = NULL) {
  if (is.null(policy)) {
    active_rules <- get_active_rules()
  } else {
    active_rules <- policy$rules %||% get_active_rules()
  }

  output_rules <- purrr::keep(active_rules, ~ .x$type == "output")

  findings <- purrr::keep(output_rules, function(rule) {
    stringr::str_detect(text, stringr::regex(rule$pattern, ignore_case = TRUE))
  })

  score <- score_findings(findings)
  band <- get_band(score)
  action <- decide_action(score, policy, findings = findings)
  redaction <- redact_text(text, findings)

  structure(
    list(
      passed = length(findings) == 0L,
      score = score,
      band = band,
      findings = findings,
      action = action,
      text_original = text,
      text_clean = redaction$text,
      redaction_log = redaction$redaction_log,
      method = "rules"
    ),
    class = "scan_report"
  )
}
