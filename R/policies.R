#' Load a Policy Preset
#'
#' Returns a named policy configuration containing the rules and thresholds
#' appropriate for a specific regulatory or industry context.
#'
#' @param name Character. One of:
#'   * `"pharma_gxp"` — Pharmaceutical GxP-compliant preset. Strictest
#'     thresholds. Includes PHI/CDISC-specific rules, efficacy claim checks,
#'     and diagnosis blocking.
#'   * `"enterprise_default"` — General enterprise preset. Covers secrets,
#'     common PII, and injection rules with standard thresholds.
#'   * `"finance_guard"` — Financial services preset. Adds financial advice
#'     detection and credit card patterns.
#'   * `"legal_guard"` — Legal industry preset. Adds legal opinion
#'     detection rules.
#'
#' @return A named list with elements:
#'   \describe{
#'     \item{`name`}{Character. The policy name.}
#'     \item{`rules`}{A list of rule objects applicable to this policy.}
#'     \item{`thresholds`}{A named list with `block`, `redact`, and `warn`
#'       score thresholds.}
#'   }
#'
#' @seealso [scan_prompt()], [secure_chat()], [decide_action()]
#'
#' @examples
#' # Load the pharma GxP policy
#' policy <- policy_preset("pharma_gxp")
#' policy$name
#' length(policy$rules)
#' policy$thresholds
#'
#' # Load the enterprise default policy
#' policy <- policy_preset("enterprise_default")
#' length(policy$rules)
#'
#' # Use a policy with scan_prompt
#' report <- scan_prompt(
#'   "Patient USUBJID-042 enrolled at site.",
#'   policy = policy_preset("pharma_gxp")
#' )
#' report$action
#'
#' @export
policy_preset <- function(name) {
  if (!rlang::is_string(name)) {
    abort_input_validation(
      arg      = "name",
      expected = "a single character string",
      got      = paste0("{.obj_type_friendly {name}}"),
      fn       = "policy_preset"
    )
  }

  all_rules <- get_active_rules()

  presets <- list(
    pharma_gxp = list(
      name       = "pharma_gxp",
      thresholds = list(block = 80, redact = 40, warn = 15)
    ),
    enterprise_default = list(
      name       = "enterprise_default",
      thresholds = list(block = 100, redact = 50, warn = 20)
    ),
    finance_guard = list(
      name       = "finance_guard",
      thresholds = list(block = 90, redact = 45, warn = 20)
    ),
    legal_guard = list(
      name       = "legal_guard",
      thresholds = list(block = 90, redact = 45, warn = 20)
    )
  )

  if (!name %in% names(presets)) {
    abort_policy_error(
      "Unknown policy preset: {.val {name}}.",
      "i" = "Available presets: {.val {names(presets)}}.",
      "i" = "See {.code ?policy_preset} for preset descriptions and use cases."
    )
  }

  preset <- presets[[name]]

  # Filter rules to those tagged for this policy
  preset$rules <- purrr::keep(all_rules, function(rule) {
    name %in% rule$policy_tags
  })

  preset
}