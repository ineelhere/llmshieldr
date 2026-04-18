#' Example prompts
#'
#' @export
example_prompts <- function() {
  # Return bundled examples
  read.csv(system.file("extdata", "example_prompts.csv", package = "llmshieldr"))
}