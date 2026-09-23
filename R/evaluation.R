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
#' @param show_stats Show total evaluation time, token estimate, and network
#'   status as messages.
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
                                    scanners = scanner_options(),
                                    show_stats = FALSE) {
  stats <- .stats_begin(show_stats, "evaluate_security_cases")
  on.exit(.stats_end(stats), add = TRUE)
  .stats_track_reviewer(stats, reviewer, checks)
  if (is.null(cases)) {
    path <- system.file("extdata", "security_eval_cases.csv", package = "llmshieldr")
    cases <- utils::read.csv(path, stringsAsFactors = FALSE,
                             encoding = "UTF-8")
  }
  if (!is.data.frame(cases)) {
    cli::cli_abort("{.arg cases} must be a data frame or {.code NULL}.")
  }
  .stats_text_tokens(stats, paste(as.character(cases$text), collapse = "\n"))
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
      rule_ids = paste(unique(vapply(report$findings, function(finding) finding$rule_id %||% "unknown", character(1))), collapse = ","),
      stringsAsFactors = FALSE
    )
  }
  do.call(rbind, rows)
}

#' Summarize a labeled security evaluation
#'
#' Calculates detection sensitivity, benign false-positive rate, action
#' accuracy, Wilson 95% confidence intervals, and p50/p95 latency from
#' [evaluate_security_cases()] output.
#'
#' @param results Evaluation result data frame.
#' @param positive_actions Actions counted as a detected risk.
#' @param show_stats Show calculation time and available usage metrics.
#'
#' @return A one-row data frame of metrics.
#' @examples
#' results <- evaluate_security_cases()
#' summarize_security_evaluation(results)
#' @export
summarize_security_evaluation <- function(results,
                                          positive_actions = c("redact", "block"),
                                          show_stats = FALSE) {
  stats <- .stats_begin(show_stats, "summarize_security_evaluation")
  on.exit(.stats_end(stats), add = TRUE)
  if (!is.data.frame(results)) cli::cli_abort("{.arg results} must be a data frame.")
  required <- c("label", "actual_action", "matched", "latency_ms")
  missing <- setdiff(required, names(results))
  if (length(missing) > 0L) cli::cli_abort("{.arg results} is missing required column{?s}: {.field {missing}}.")
  benign <- tolower(as.character(results$label)) == "benign"
  detected <- results$actual_action %in% positive_actions
  positive <- !benign
  sensitivity <- .rate_ci(sum(detected & positive), sum(positive))
  false_positive <- .rate_ci(sum(detected & benign), sum(benign))
  accuracy <- .rate_ci(sum(results$matched, na.rm = TRUE), nrow(results))
  data.frame(
    cases = nrow(results),
    sensitivity = sensitivity[["estimate"]],
    sensitivity_low = sensitivity[["low"]],
    sensitivity_high = sensitivity[["high"]],
    false_positive_rate = false_positive[["estimate"]],
    false_positive_low = false_positive[["low"]],
    false_positive_high = false_positive[["high"]],
    action_accuracy = accuracy[["estimate"]],
    action_accuracy_low = accuracy[["low"]],
    action_accuracy_high = accuracy[["high"]],
    latency_p50_ms = as.numeric(stats::quantile(results$latency_ms, 0.5, na.rm = TRUE, names = FALSE)),
    latency_p95_ms = as.numeric(stats::quantile(results$latency_ms, 0.95, na.rm = TRUE, names = FALSE)),
    stringsAsFactors = FALSE
  )
}

#' Compare policy decisions on the same corpus
#'
#' @param cases Evaluation corpus accepted by [evaluate_security_cases()].
#' @param from Baseline policy.
#' @param to Candidate policy.
#' @inheritParams evaluate_security_cases
#' @param show_stats Show execution statistics as messages.
#'
#' @return A data frame with baseline and candidate actions, rules, and a
#'   `changed` flag.
#' @examples
#' \dontrun{
#' diff <- compare_policies(
#'   NULL,
#'   policy("enterprise_default"),
#'   policy("comprehensive")
#' )
#' subset(diff, changed)
#' }
#' @export
compare_policies <- function(cases = NULL,
                             from,
                             to,
                             reviewer = NULL,
                             checks = "rules",
                             redaction = NULL,
                             scanners = scanner_options(),
                             show_stats = FALSE) {
  stats <- .stats_begin(show_stats, "compare_policies")
  on.exit(.stats_end(stats), add = TRUE)
  baseline <- evaluate_security_cases(cases, from, reviewer, checks, redaction, scanners)
  candidate <- evaluate_security_cases(cases, to, reviewer, checks, redaction, scanners)
  if (!identical(baseline$id, candidate$id)) cli::cli_abort("Policy evaluations returned different case ordering.")
  data.frame(
    id = baseline$id,
    stage = baseline$stage,
    category = baseline$category,
    from_action = baseline$actual_action,
    to_action = candidate$actual_action,
    from_rules = baseline$rule_ids,
    to_rules = candidate$rule_ids,
    changed = baseline$actual_action != candidate$actual_action | baseline$rule_ids != candidate$rule_ids,
    stringsAsFactors = FALSE
  )
}

.rate_ci <- function(successes, total, z = 1.959964) {
  if (total == 0L) return(c(estimate = NA_real_, low = NA_real_, high = NA_real_))
  p <- successes / total
  denominator <- 1 + z^2 / total
  center <- (p + z^2 / (2 * total)) / denominator
  margin <- z * sqrt((p * (1 - p) + z^2 / (4 * total)) / total) / denominator
  c(estimate = p, low = max(0, center - margin), high = min(1, center + margin))
}
