#' llmshieldr: Security Scanning and Policy Enforcement for LLM Workflows
#'
#' `llmshieldr` provides rule-based safety controls for LLM workflows in R.
#' The package combines prompt and context scanning, optional redaction,
#' policy-based action selection, postflight output checks, and audit logging.
#'
#' It was designed with regulated workflows in mind, especially pharma and
#' clinical settings, but the package API is general enough for broader
#' enterprise use cases.
#'
#' ## Main entry points
#'
#' - [secure_chat()] for an end-to-end wrapped LLM interaction
#' - [preflight_check()] and [scan_prompt()] for scan-only use
#' - [scan_output()] for postflight output checks
#' - [policy_preset()] for built-in governance presets
#' - [write_audit_log()] for JSON Lines audit export
#'
#' ## Learn more
#'
#' - `vignette("getting-started", package = "llmshieldr")`
#' - `?secure_chat`
#' - `?policy_preset`
#'
#' @keywords internal
"_PACKAGE"
