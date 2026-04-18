#' Scan output for unsafe content
#'
#' @param text Character string to scan
#' @return scan_report object
scan_output <- function(text) {
  rules <- rule_bank[sapply(rule_bank, `[[`, "type") == "output"]
  findings <- list()
  for (rule in rules) {
    if (grepl(rule$pattern, text, ignore.case = TRUE)) {
      findings <- c(findings, list(rule))
    }
  }
  score <- score_findings(findings)
  band <- get_band(score)
  action <- decide_action(score, list())  # placeholder
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