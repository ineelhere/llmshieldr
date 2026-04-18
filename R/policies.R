#' Policy presets
#'
#' @export
policy_preset <- function(name) {
  if (name == "pharma_gxp") {
    rules <- rule_bank[sapply(rule_bank, function(r) "pharma_gxp" %in% r$policy_tags)]
    list(name = "pharma_gxp", rules = rules)
  } else if (name == "enterprise_default") {
    rules <- rule_bank[sapply(rule_bank, function(r) "enterprise_default" %in% r$policy_tags)]
    list(name = "enterprise_default", rules = rules)
  } else {
    stop("Unknown policy")
  }
}