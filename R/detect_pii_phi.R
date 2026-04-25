#' Detect PII / PHI in Text
#'
#' Scans a text string for Personally Identifiable Information (PII) and
#' Protected Health Information (PHI). Detects email addresses, phone numbers,
#' Social Security Numbers, dates of birth, medical record numbers, CDISC
#' subject identifiers, patient narratives, and credit card numbers.
#'
#' @param text A single character string to scan.
#'
#' @return A list of matched rule objects. Returns an empty list if no PII/PHI
#'   is found.
#'
#' @seealso [scan_prompt()], [preflight_check()], [policy_preset()]
#'
#' @examples
#' # No PII — returns empty list
#' detect_pii_phi("Explain the SDTM IG structure.")
#'
#' # CDISC subject identifier detected
#' detect_pii_phi("Patient USUBJID: STUDY01-SITE03-SUBJ042")
#'
#' # Email address detected
#' detect_pii_phi("Contact the PI at jane.doe@pharma.com for details.")
#'
#' # Phone number detected
#' detect_pii_phi("Call the site at 555-867-5309 for enrollment.")
#'
#' # SSN pattern detected
#' detect_pii_phi("SSN: 123-45-6789")
#'
#' # Medical Record Number detected
#' detect_pii_phi("MRN: A12345678")
#'
#' @keywords internal
#' @noRd
detect_pii_phi <- function(text) {
  if (!rlang::is_string(text)) {
    abort_input_validation(
      arg      = "text",
      expected = "a single character string",
      got      = paste0("{.obj_type_friendly {text}}"),
      fn       = "detect_pii_phi"
    )
  }

  rules <- purrr::keep(get_active_rules(), ~ .x$type == "phi")

  purrr::keep(rules, function(rule) {
    stringr::str_detect(text, stringr::regex(rule$pattern, ignore_case = TRUE))
  })
}
