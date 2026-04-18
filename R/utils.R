#' Preflight check
#'
#' @param prompt Character string
#' @param policy Policy list
#' @return scan_report
#' @export
preflight_check <- function(prompt, policy) {
  scan_prompt(prompt, policy)
}

#' Add rule
#'
#' @param rule List
#' @export
add_rule <- function(rule) {
  # Add to global rule_bank (simplified)
  rule_bank <<- c(rule_bank, list(rule))
}

#' Remove rule
#'
#' @param id Character
#' @export
remove_rule <- function(id) {
  # Remove from rule_bank
  idx <- sapply(rule_bank, `[[`, "id") == id
  if (any(idx)) {
    rule_bank <<- rule_bank[!idx]
  }
}

#' List rules
#'
#' @export
list_rules <- function() {
  rule_bank
}

#' Explain findings
#'
#' @param findings List
#' @export
explain_findings <- function(findings) {
  sapply(findings, function(f) glue::glue("{f$description}. Severity: {f$severity}. Action: {f$action}. OWASP: {f$owasp}."))
}