#' Evaluate scanner behavior on a labeled corpus
#'
#' `evaluate_security_cases()` runs llmshieldr scanners over a small labeled
#' corpus and returns action-level metrics. It is designed for repeatable local
#' evaluation, release notes, and adoption reviews; it is not a substitute for
#' a full red-team benchmark.
#'
#' @details
#' The input corpus should contain at least `stage`, `text`, and
#' `expected_action` columns. If `stage` is `"output"`, rows are scanned with
#' [scan_output()]. If `stage` is `"context"`, each row is scanned as a one-row
#' context data frame with [scan_context()]. All other stages are scanned with
#' [scan_prompt()].
#'
#' The returned data frame includes per-case latency in milliseconds and a
#' Boolean `matched` column. Use the summary columns to calculate detection
#' rate, false-positive rate, action accuracy, and latency percentiles in
#' vignettes or release notes.
#'
#' @param cases Optional data frame. If `NULL`, the packaged
#'   `inst/extdata/security_eval_cases.csv` corpus is loaded.
#' @param policy A `shieldr_policy` or built-in policy name.
#' @param reviewer Optional reviewer function or object with `$chat()`.
#' @param checks One of `"rules"`, `"nlp"`, `"llm"`, or `"both"`.
#' @param redaction Optional redaction strategy from [redaction_strategy()].
#' @param scanners Optional scanner configuration from [scanner_options()].
#'
#' @return A data frame with case metadata, expected and actual actions,
#'   `matched`, `latency_ms`, and `n_findings`.
#' @examples
#' \dontrun{
#' results <- evaluate_security_cases(policy = "comprehensive")
#' mean(results$matched)
#' }
#' @export
evaluate_security_cases <- function(cases = NULL,
                                    policy = "comprehensive",
                                    reviewer = NULL,
                                    checks = "rules",
                                    redaction = NULL,
                                    scanners = scanner_options()) {
  if (is.null(cases)) {
    path <- system.file("extdata", "security_eval_cases.csv", package = "llmshieldr")
    cases <- utils::read.csv(path, stringsAsFactors = FALSE)
  }
  if (!is.data.frame(cases)) {
    cli::cli_abort("{.arg cases} must be a data frame or {.code NULL}.")
  }
  required <- c("stage", "text", "expected_action")
  missing <- setdiff(required, names(cases))
  if (length(missing) > 0L) {
    cli::cli_abort("{.arg cases} is missing required column{?s}: {.field {missing}}.")
  }

  rows <- vector("list", nrow(cases))
  for (i in seq_len(nrow(cases))) {
    stage <- tolower(as.character(cases$stage[[i]]))
    text <- as.character(cases$text[[i]])
    t0 <- proc.time()[["elapsed"]]
    report <- switch(
      stage,
      output = scan_output(
        text,
        policy = policy,
        reviewer = reviewer,
        checks = checks,
        redaction = redaction,
        scanners = scanners
      ),
      context = scan_context(
        data.frame(text = text, stringsAsFactors = FALSE),
        policy = policy,
        reviewer = reviewer,
        checks = checks,
        redaction = redaction,
        scanners = scanners
      )[[1L]],
      scan_prompt(
        text,
        policy = policy,
        reviewer = reviewer,
        checks = checks,
        redaction = redaction,
        scanners = scanners
      )
    )
    latency_ms <- .elapsed_ms(t0)
    expected <- as.character(cases$expected_action[[i]])
    rows[[i]] <- data.frame(
      id = if ("id" %in% names(cases)) as.character(cases$id[[i]]) else as.character(i),
      stage = stage,
      category = if ("category" %in% names(cases)) as.character(cases$category[[i]]) else NA_character_,
      owasp = if ("owasp" %in% names(cases)) as.character(cases$owasp[[i]]) else NA_character_,
      label = if ("label" %in% names(cases)) as.character(cases$label[[i]]) else NA_character_,
      expected_action = expected,
      actual_action = report$action,
      matched = identical(report$action, expected),
      latency_ms = latency_ms,
      n_findings = length(report$findings),
      stringsAsFactors = FALSE
    )
  }
  do.call(rbind, rows)
}
