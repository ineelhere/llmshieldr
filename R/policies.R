#' Policy presets
#'
#' @export
policy_preset <- function(name) {
  if (name == "pharma_gxp") {
    # Return pharma_gxp policy
    list(name = "pharma_gxp", rules = rule_bank)
  } else {
    stop("Unknown policy")
  }
}