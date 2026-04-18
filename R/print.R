#' Print methods
#'
#' @export
print.scan_report <- function(x, ...) {
  cat("Scan Report\n")
  cat("Passed:", x$passed, "\n")
  cat("Score:", x$score, "\n")
  # etc.
}

#' @export
print.shield_audit <- function(x, ...) {
  cat("Shield Audit\n")
  cat("Timestamp:", x$timestamp, "\n")
  # etc.
}

#' @export
print.secure_result <- function(x, ...) {
  cat("Secure Result\n")
  cat("Output:", x$output, "\n")
  # etc.
}