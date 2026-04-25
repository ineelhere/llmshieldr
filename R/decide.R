#' Decide Action Based on Score and Policy
#'
#' Translates a numeric risk score and policy configuration into an action
#' string. The action determines how `llmshieldr` handles the prompt or
#' output: block it, redact risky content, warn the user, or allow it through.
#' Rule-level actions are also respected, so a single `"block"` finding can
#' escalate the final decision even when thresholds alone would not.
#'
#' @param score A single numeric risk score from the active findings.
#' @param policy A policy list (from [policy_preset()]). May contain a
#'   `thresholds` element with custom `block`, `redact`, and `warn` values.
#'   If `NULL` or missing `thresholds`, built-in defaults are used:
#'   block \eqn{\geq 100}, redact \eqn{\geq 50}, warn \eqn{\geq 20}.
#' @param findings Optional list of rule objects. When supplied, the strongest
#'   `action` found in the rules is combined with the threshold-based action.
#'
#' @return A character string: `"block"`, `"redact"`, `"warn"`, or `"allow"`.
#'
#' @seealso [scan_prompt()], [scan_output()], [policy_preset()]
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
#' # Rule-level actions can escalate the final decision
#' findings <- list(list(action = "block"))
#' decide_action(10, strict_policy, findings)
#'
#' @keywords internal
#' @noRd
decide_action <- function(score, policy = NULL, findings = list()) {
  if (!is.numeric(score) || length(score) != 1L) {
    abort_input_validation(
      arg      = "score",
      expected = "a single numeric value",
      got      = paste0("{.obj_type_friendly {score}}"),
      fn       = "decide_action"
    )
  }

  thresholds <- if (!is.null(policy) && !is.null(policy$thresholds)) {
    policy$thresholds
  } else {
    list(block = 100, redact = 50, warn = 20)
  }

  threshold_action <- if (score >= thresholds$block) {
    "block"
  } else if (score >= thresholds$redact) {
    "redact"
  } else if (score >= thresholds$warn) {
    "warn"
  } else {
    "allow"
  }

  rule_action <- .strongest_finding_action(findings)

  .strongest_action(c(threshold_action, rule_action))
}


#' @noRd
#' @keywords internal
.action_levels <- c("allow", "warn", "redact", "block")


#' @noRd
#' @keywords internal
.strongest_action <- function(actions) {
  actions <- stats::na.omit(actions)
  ranks <- match(actions, .action_levels)
  ranks <- stats::na.omit(ranks)
  if (length(ranks) == 0L) {
    return("allow")
  }
  .action_levels[[max(ranks, na.rm = TRUE)]]
}


#' @noRd
#' @keywords internal
.strongest_finding_action <- function(findings) {
  if (length(findings) == 0L) {
    return("allow")
  }

  actions <- vapply(findings, `[[`, character(1), "action")
  .strongest_action(actions)
}
