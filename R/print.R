#' Print methods
#'
#' @export
print.scan_report <- function(x, ...) {
  cat("Scan Report\n")
  cat("Passed:", x$passed, "\n")
  cat("Score:", x$score, "(", x$band, ")\n")
  cat("Findings:", length(x$findings), "\n")
  if (length(x$findings) > 0) {
    for (f in x$findings) {
      cat(" -", f$description, "\n")
    }
  }
  cat("Action:", x$action, "\n")
}

#' @export
summary.scan_report <- function(object, ...) {
  print(object)
}

#' @export
as_tibble.scan_report <- function(x, ...) {
  tibble::tibble(
    passed = x$passed,
    score = x$score,
    band = x$band,
    findings_count = length(x$findings),
    action = x$action,
    text_original = x$text_original,
    text_clean = x$text_clean
  )
}

#' @export
print.shield_audit <- function(x, ...) {
  cat("Shield Audit\n")
  cat("Timestamp:", format(x$timestamp), "\n")
  cat("Policy:", x$policy, "\n")
  cat("Model:", x$model, "\n")
  cat("Input Score:", x$input_report$score, "\n")
  cat("Output Score:", x$output_report$score, "\n")
  cat("Final Action:", x$final_action, "\n")
}

#' @export
summary.shield_audit <- function(object, ...) {
  print(object)
}

#' @export
as_tibble.shield_audit <- function(x, ...) {
  tibble::tibble(
    timestamp = x$timestamp,
    policy = x$policy,
    model = x$model,
    provider = x$provider,
    input_score = x$input_report$score,
    output_score = x$output_report$score,
    final_action = x$final_action
  )
}

#' @export
print.secure_result <- function(x, ...) {
  cat("Secure Result\n")
  cat("Output:", substr(x$output, 1, 100), "...\n")
  print(x$risk_summary)
}

#' @export
summary.secure_result <- function(object, ...) {
  print(object)
}