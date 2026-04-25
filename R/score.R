#' Score Detection Findings
#'
#' Computes the aggregate risk score from a list of matched rule findings.
#' The score is the sum of each finding's `severity` weight. Higher scores
#' indicate greater risk.
#'
#' @param findings A list of rule objects (as returned by detector functions).
#'
#' @return A single numeric value representing the total risk score. Returns
#'   `0` for an empty findings list.
#'
#' @seealso [scan_prompt()], [scan_output()]
#'
#' @examples
#' # Score from an empty findings list
#' score_findings(list())
#'
#' # Score a single finding
#' findings <- detect_secrets("Use key sk-abc123def456ghi789jkl012mno345pq")
#' score_findings(findings)
#'
#' # Score multiple findings
#' findings <- detect_pii_phi("Patient USUBJID: STUDY01, email: test@example.com")
#' score_findings(findings)
#'
#' @keywords internal
#' @noRd
score_findings <- function(findings) {
  if (length(findings) == 0L) return(0)
  sum(purrr::map_dbl(findings, "severity"))
}


#' Get Severity Band
#'
#' Converts a numeric risk score into a human-readable severity band.
#'
#' @param score A single numeric risk score.
#'
#' @return A character string: `"critical"` (\eqn{\geq 100}), `"high"`
#'   (\eqn{\geq 50}), `"moderate"` (\eqn{\geq 20}), or `"low"` (< 20).
#'
#' @seealso [scan_prompt()], [scan_output()]
#'
#' @examples
#' get_band(0)
#' get_band(15)
#' get_band(35)
#' get_band(75)
#' get_band(150)
#'
#' @keywords internal
#' @noRd
get_band <- function(score) {
  if (!is.numeric(score) || length(score) != 1L) {
    abort_input_validation(
      arg      = "score",
      expected = "a single numeric value",
      got      = paste0("{.obj_type_friendly {score}}"),
      fn       = "get_band"
    )
  }

  if (score >= 100) {
    "critical"
  } else if (score >= 50) {
    "high"
  } else if (score >= 20) {
    "moderate"
  } else {
    "low"
  }
}
