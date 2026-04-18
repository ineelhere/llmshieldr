#' Detect PII/PHI in text
#'
#' @param text Character string to scan
#' @return List of findings
detect_pii_phi <- function(text) {
  rules <- rule_bank[sapply(rule_bank, `[[`, "type") == "phi"]
  findings <- list()
  for (rule in rules) {
    if (grepl(rule$pattern, text, ignore.case = TRUE)) {
      findings <- c(findings, list(rule))
    }
  }
  findings
}