#' Example Prompts for Testing and Demos
#'
#' Returns a bundled [tibble::tibble()] of example prompts covering safe,
#' PHI-containing, secret-leaking, and injection-laden scenarios. Useful
#' for demonstrations, unit testing, and quick evaluation of detection
#' rules.
#'
#' @return A [tibble::tibble()] with columns:
#'   \describe{
#'     \item{`prompt`}{Character. The example prompt text.}
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
#' # Scan each example prompt
#' reports <- lapply(prompts$prompt, scan_prompt)
#' actions <- vapply(reports, `[[`, character(1), "action")
#' data.frame(type = prompts$type, action = actions)
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
  tibble::as_tibble(utils::read.csv(path, stringsAsFactors = FALSE))
}