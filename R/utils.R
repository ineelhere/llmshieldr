#' Preflight check
#'
#' @param prompt Character string
#' @param policy Policy list
#' @return scan_report
#' @export
preflight_check <- function(prompt, policy) {
  scan_prompt(prompt)
}

#' Add rule
#'
#' @param rule List
#' @export
add_rule <- function(rule) {
  # Add to rule_bank
}

#' Remove rule
#'
#' @param id Character
#' @export
remove_rule <- function(id) {
  # Remove from rule_bank
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
  # Return explanations
}