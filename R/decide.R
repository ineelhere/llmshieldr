#' Decide action based on score and policy
#'
#' @param score Numeric score
#' @param policy Policy list
#' @return Action string
decide_action <- function(score, policy) {
  if (score >= 100) "block" else if (score >= 50) "redact" else if (score >= 20) "warn" else "allow"
}