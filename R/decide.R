#' Decide Action Based on Score and Policy
#'
#' Translates a numeric risk score and policy configuration into an action
#' string. The action determines how `llmshieldr` handles the prompt or
#' output: block it, redact risky content, warn the user, or allow it through.
#'
#' @param score A single numeric risk score (from [score_findings()]).
#' @param policy A policy list (from [policy_preset()]). May contain a
#'   `thresholds` element with custom `block`, `redact`, and `warn` values.
#'   If `NULL` or missing `thresholds`, built-in defaults are used:
#'   block \eqn{\geq 100}, redact \eqn{\geq 50}, warn \eqn{\geq 20}.
#'
#' @return A character string: `"block"`, `"redact"`, `"warn"`, or `"allow"`.
#'
#' @seealso [score_findings()], [get_band()], [policy_preset()]
#'
#' @examples
#' # Default thresholds
#' decide_action(0, NULL)
#' decide_action(25, NULL)
#' decide_action(60, NULL)
#' decide_action(100, NULL)
#'
#' # With a policy that has custom thresholds
#' strict_policy <- list(
#'   name = "strict",
#'   thresholds = list(block = 80, redact = 40, warn = 10)
#' )
#' decide_action(50, strict_policy)
#'
#' @export
decide_action <- function(score, policy) {
  if (!is.numeric(score) || length(score) != 1L) {
    abort_input_validation(
      arg      = "score",
      expected = "a single numeric value",
      got      = paste0("{.obj_type_friendly {score}}"),
      fn       = "decide_action"
    )
  }

  # Extract thresholds from policy, or use defaults
 thresholds <- if (!is.null(policy) && !is.null(policy$thresholds)) {
    policy$thresholds
  } else {
    list(block = 100, redact = 50, warn = 20)
  }

  if (score >= thresholds$block) {
    "block"
  } else if (score >= thresholds$redact) {
    "redact"
  } else if (score >= thresholds$warn) {
    "warn"
  } else {
    "allow"
  }
}