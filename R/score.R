#' Score findings
#'
#' @param findings List of findings
#' @return Numeric score
score_findings <- function(findings) {
  sum(sapply(findings, `[[`, "severity"))
}

#' Get severity band
#'
#' @param score Numeric score
#' @return Character band
get_band <- function(score) {
  if (score >= 100) "critical" else if (score >= 50) "high" else if (score >= 20) "moderate" else "low"
}