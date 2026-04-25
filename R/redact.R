#' Redact Risky Content from Text
#'
#' Replaces matched patterns in `text` with typed redaction masks (e.g.,
#' `[REDACTED_API_KEY]`, `[REDACTED_EMAIL]`). Returns both the cleaned text
#' and a redaction log for audit purposes.
#'
#' @param text A single character string to sanitise.
#' @param findings A list of rule objects (as returned by detector functions).
#'   Each rule must contain `pattern` and `mask` fields.
#'
#' @return A named list with two elements:
#'   \describe{
#'     \item{`text`}{The redacted text string.}
#'     \item{`redaction_log`}{A list of lists, each containing `rule_id`,
#'       `original_match`, and `mask` for every replacement made.}
#'   }
#'
#' @seealso [scan_prompt()], [scan_output()], [secure_chat()]
#'
#' @examples
#' # Redact an email address
#' findings <- detect_pii_phi("Contact: jane.doe@pharma.com")
#' result <- redact_text("Contact: jane.doe@pharma.com", findings)
#' result$text
#' result$redaction_log
#'
#' # Redact a subject identifier
#' findings <- detect_pii_phi("Patient USUBJID was enrolled.")
#' result <- redact_text("Patient USUBJID was enrolled.", findings)
#' result$text
#'
#' # No findings — text unchanged
#' result <- redact_text("Safe prompt about SDTM.", list())
#' result$text
#'
#' @keywords internal
#' @noRd
redact_text <- function(text, findings) {
  if (!rlang::is_string(text)) {
    abort_input_validation(
      arg      = "text",
      expected = "a single character string",
      got      = paste0("{.obj_type_friendly {text}}"),
      fn       = "redact_text"
    )
  }

  redaction_log <- list()

  for (finding in findings) {
    # Capture what was matched before replacing
    matches <- stringr::str_extract_all(
      text,
      stringr::regex(finding$pattern, ignore_case = TRUE)
    )[[1]]

    if (length(matches) > 0L) {
      for (match in matches) {
        redaction_log <- c(redaction_log, list(list(
          rule_id        = finding$id,
          original_match = match,
          mask           = finding$mask
        )))
      }

      text <- stringr::str_replace_all(
        text,
        stringr::regex(finding$pattern, ignore_case = TRUE),
        finding$mask
      )
    }
  }

  list(
    text          = text,
    redaction_log = redaction_log
  )
}
