#' Redact text
#'
#' @param text Character string
#' @param findings List of findings
#' @return Redacted text
redact_text <- function(text, findings) {
  for (finding in findings) {
    text <- stringr::str_replace_all(text, finding$pattern, finding$mask)
  }
  text
}