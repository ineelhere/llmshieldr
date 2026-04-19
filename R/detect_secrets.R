#' Detect Secrets in Text
#'
#' Scans a text string for embedded credentials, API keys, tokens, passwords,
#' connection strings, and private key blocks. Uses the `"secret"` subset of
#' the active rule bank.
#'
#' @param text A single character string to scan.
#'
#' @return A list of matched rule objects. Each element is a list with fields
#'   `id`, `type`, `pattern`, `severity`, `action`, `mask`, `description`,
#'   `owasp`, and `policy_tags`. Returns an empty list if no secrets are found.
#'
#' @seealso [detect_pii_phi()], [detect_injection()], [scan_prompt()]
#'
#' @examples
#' # No secrets — returns empty list
#' detect_secrets("Summarize the AE domain structure in SDTM.")
#'
#' # OpenAI-style API key detected
#' detect_secrets("Use key sk-abc123def456ghi789jkl012mno345pq")
#'
#' # Bearer token detected
#' detect_secrets("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
#'
#' # Password in a config line
#' detect_secrets("password = SuperSecret123!")
#'
#' # GitHub PAT detected
#' detect_secrets("Set GITHUB_PAT=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789")
#'
#' @export
detect_secrets <- function(text) {
  if (!rlang::is_string(text)) {
    abort_input_validation(
      arg      = "text",
      expected = "a single character string",
      got      = paste0("{.obj_type_friendly {text}}"),
      fn       = "detect_secrets"
    )
  }

  rules <- purrr::keep(get_active_rules(), ~ .x$type == "secret")

  purrr::keep(rules, function(rule) {
    stringr::str_detect(text, stringr::regex(rule$pattern, ignore_case = TRUE))
  })
}