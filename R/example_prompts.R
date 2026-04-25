#' Example Scenarios for Testing and Demos
#'
#' Returns a bundled [tibble::tibble()] of realistic prompt scenarios mapped
#' to common `llmshieldr` workflows such as `scan_prompt()`, `scan_context()`,
#' `preflight_check()`, `secure_chat()`, and `shield_ollama()`. Useful for
#' demos, docs, unit tests, and quick regression checks.
#'
#' @return A [tibble::tibble()] with columns:
#'   \describe{
#'     \item{`prompt`}{Character. The example prompt text.}
#'     \item{`feature`}{Character. The main `llmshieldr` entry point the
#'       scenario is designed to demonstrate.}
#'     \item{`policy`}{Character. The recommended preset to use when scanning
#'       the scenario.}
#'     \item{`type`}{Character. Category: `"safe"`, `"phi"`, `"secret"`,
#'       or `"injection"`.}
#'     \item{`description`}{Character. Brief description of what the prompt
#'       demonstrates.}
#'     \item{`expected_action`}{Character. The expected scanner action:
#'       `"allow"`, `"warn"`, `"redact"`, or `"block"`.}
#'   }
#'
#' @seealso [scan_prompt()], [preflight_check()]
#'
#' @examples
#' # Load the example prompts
#' prompts <- example_prompts()
#' prompts
#'
#' # Scan each example with its recommended policy
#' reports <- lapply(seq_len(nrow(prompts)), function(i) {
#'   scan_prompt(
#'     prompts$prompt[[i]],
#'     policy = policy_preset(prompts$policy[[i]])
#'   )
#' })
#' actions <- vapply(reports, `[[`, character(1), "action")
#' data.frame(
#'   feature = prompts$feature,
#'   type = prompts$type,
#'   expected_action = prompts$expected_action,
#'   observed_action = actions
#' )
#'
#' @export
example_prompts <- function() {
  path <- system.file("extdata", "example_prompts.csv", package = "llmshieldr")
  if (path == "") {
    abort_not_found(
      "Example prompts file not found.",
      "x" = "Could not locate {.file inst/extdata/example_prompts.csv} in the package.",
      "i" = "Reinstall {.pkg llmshieldr} with {.code devtools::install()} or {.code install.packages('llmshieldr')}."
    )
  }
  df <- utils::read.csv(path, stringsAsFactors = FALSE)
  # Filter out empty rows that might come from trailing newlines
  df <- df[!is.na(df$prompt) & df$prompt != "", ]
  tibble::as_tibble(df)
}
