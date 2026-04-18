#' Scan prompt with all detectors
#'
#' @param text Character string to scan
#' @return scan_report object
scan_prompt <- function(text) {
  # Run all detectors
  findings <- c(
    detect_secrets(text),
    detect_pii_phi(text),
    detect_injection(text)
  )
  score <- score_findings(findings)
  band <- get_band(score)
  action <- decide_action(score, list())  # placeholder policy
  # Redact
  text_clean <- redact_text(text, findings)
  # Create scan_report
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