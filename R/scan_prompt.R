#' Scan prompt with all detectors
#'
#' @param text Character string to scan
#' @param policy Policy list
#' @return scan_report object
scan_prompt <- function(text, policy = NULL) {
  if (is.null(policy)) policy <- list(rules = rule_bank)
  rules <- policy$rules
  secret_rules <- rules[sapply(rules, `[[`, "type") == "secret"]
  phi_rules <- rules[sapply(rules, `[[`, "type") == "phi"]
  injection_rules <- rules[sapply(rules, `[[`, "type") == "injection"]
  findings <- list()
  for (rule in c(secret_rules, phi_rules, injection_rules)) {
    if (grepl(rule$pattern, text, ignore.case = TRUE)) {
      findings <- c(findings, list(rule))
    }
  }
  score <- score_findings(findings)
  band <- get_band(score)
  action <- decide_action(score, policy)
  text_clean <- redact_text(text, findings)
  structure(list(
    passed = length(findings) == 0,
    score = score,
    band = band,
    findings = findings,
    action = action,
    text_original = text,
    text_clean = text_clean
  ), class = "scan_report")
}