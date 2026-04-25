#' llmshieldr: Security Scanning and Policy Enforcement for LLM Workflows
#'
#' `llmshieldr` provides safety controls for LLM workflows in R. The package
#' combines prompt and context scanning, optional redaction, policy-based
#' action selection, postflight output checks, audit logging, and optional
#' local reviewer-model checks through Ollama-compatible chat clients.
#'
#' It was designed with regulated workflows in mind, especially pharma and
#' clinical settings, but the package API is general enough for broader
#' enterprise use cases.
#'
#' ## Main entry points
#'
#' - [scan_prompt()] and [preflight_check()] to check prompts before sending
#' - [scan_context()] to check retrieved or pasted context
#' - [scan_output()] to review model replies
#' - [secure_chat()] for a bring-your-own-provider guarded workflow
#' - [shield_ollama()] for the easiest local Ollama setup
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
