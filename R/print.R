# ── print / summary / format / as_tibble methods ─────────────────────────────
# All S3 methods for scan_report, shield_audit, and secure_result.

# ── scan_report ──────────────────────────────────────────────────────────────

#' Print a Scan Report
#'
#' @param x A `scan_report` object.
#' @param ... Additional arguments (ignored).
#'
#' @return Invisibly returns `x`.
#'
#' @examples
#' report <- scan_prompt("Patient USUBJID-042 enrolled.")
#' print(report)
#'
#' @export
print.scan_report <- function(x, ...) {
  cli::cli_h2("llmshieldr Scan Report")

  if (x$passed) {
    cli::cli_alert_success("Status: {.strong PASSED} \u2714")
  } else {
    cli::cli_alert_danger("Status: {.strong FAILED} \u2718")
  }

  cli::cli_alert_info("Score: {.val {x$score}} | Band: {.val {x$band}} | Action: {.val {x$action}}")
  if (!is.null(x$method)) {
    cli::cli_alert_info("Checks used: {.val {x$method}}")
  }

  if (length(x$findings) > 0L) {
    cli::cli_h3("Findings ({length(x$findings)})")
    for (f in x$findings) {
      icon <- switch(
        f$action,
        block  = "\u274c",
        redact = "\U0001f6e1\ufe0f",
        warn   = "\u26a0\ufe0f",
        "\u2139\ufe0f"
      )
      cli::cli_li("{icon} [{f$owasp}] {f$description} (severity: {f$severity})")
    }
  }

  if (!x$passed && !is.null(x$text_clean)) {
    cli::cli_h3("Redacted Text")
    cli::cli_text("{.code {x$text_clean}}")
  }

  invisible(x)
}

#' @rdname print.scan_report
#' @export
summary.scan_report <- function(object, ...) {
  cli::cli_h2("Scan Report Summary")
  cli::cli_dl(c(
    "Passed"   = as.character(object$passed),
    "Score"    = as.character(object$score),
    "Band"     = object$band,
    "Findings" = as.character(length(object$findings)),
    "Action"   = object$action
  ))
  invisible(object)
}

#' @rdname print.scan_report
#' @export
as_tibble.scan_report <- function(x, ...) {
  finding_ids <- if (length(x$findings) > 0L) {
    paste(vapply(x$findings, `[[`, character(1), "id"), collapse = ", ")
  } else {
    NA_character_
  }

  tibble::tibble(
    passed         = x$passed,
    score          = x$score,
    band           = x$band,
    findings_count = length(x$findings),
    finding_ids    = finding_ids,
    action         = x$action,
    text_original  = x$text_original,
    text_clean     = x$text_clean
  )
}


# ── shield_audit ─────────────────────────────────────────────────────────────

#' Print a Shield Audit Record
#'
#' @param x A `shield_audit` object.
#' @param ... Additional arguments (ignored).
#'
#' @return Invisibly returns `x`.
#'
#' @examples
#' input_rpt <- scan_prompt("Safe SDTM question.")
#' output_rpt <- scan_output("AE domain captures events.")
#' audit <- shield_audit(
#'   policy = "pharma_gxp", model = "gemma3:4b",
#'   provider = "ollama", input_report = input_rpt,
#'   output_report = output_rpt, final_action = "allow"
#' )
#' print(audit)
#'
#' @export
print.shield_audit <- function(x, ...) {
  cli::cli_h2("llmshieldr Audit Record")
  cli::cli_dl(c(
    "Timestamp"    = format(x$timestamp, "%Y-%m-%d %H:%M:%S %Z"),
    "Policy"       = x$policy,
    "Model"        = x$model,
    "Provider"     = x$provider,
    "Reviewer"     = x$reviewer_model %||% "N/A",
    "Checks"       = x$checks %||% "rules",
    "Input Score"  = paste0(x$input_report$score %||% "N/A",
                           " (", x$input_report$band %||% "N/A", ")"),
    "Output Score" = paste0(x$output_report$score %||% "N/A",
                           " (", x$output_report$band %||% "N/A", ")"),
    "Action"       = x$final_action,
    "Redactions"   = as.character(length(x$redactions))
  ))

  invisible(x)
}

#' @rdname print.shield_audit
#' @export
summary.shield_audit <- function(object, ...) {
  print(object)
}

#' @rdname print.shield_audit
#' @export
as_tibble.shield_audit <- function(x, ...) {
  tibble::tibble(
    timestamp       = x$timestamp,
    policy          = x$policy,
    model           = x$model,
    provider        = x$provider,
    reviewer_model  = x$reviewer_model %||% NA_character_,
    reviewer_provider = x$reviewer_provider %||% NA_character_,
    checks          = x$checks %||% NA_character_,
    input_score     = x$input_report$score %||% NA_real_,
    input_band      = x$input_report$band %||% NA_character_,
    output_score    = x$output_report$score %||% NA_real_,
    output_band     = x$output_report$band %||% NA_character_,
    final_action    = x$final_action,
    redaction_count = length(x$redactions)
  )
}


# ── secure_result ────────────────────────────────────────────────────────────

#' Print a Secure Result
#'
#' @param x A `secure_result` object.
#' @param ... Additional arguments (ignored).
#'
#' @return Invisibly returns `x`.
#'
#' @export
print.secure_result <- function(x, ...) {
  cli::cli_h2("llmshieldr Secure Result")

  cli::cli_h3("Model Output")
  output_preview <- if (nchar(x$output) > 300L) {
    paste0(substr(x$output, 1, 300), "...")
  } else {
    x$output
  }
  cli::cli_text(output_preview)

  cli::cli_h3("Risk Summary")
  cli::cli_dl(c(
    "Input"  = paste0(x$risk_summary$input_score, " (", x$risk_summary$input_band, ")"),
    "Output" = paste0(x$risk_summary$output_score, " (", x$risk_summary$output_band, ")"),
    "Rules Triggered" = as.character(x$risk_summary$rules_triggered),
    "Action" = x$risk_summary$action_taken,
    "Checks" = x$risk_summary$checks_used %||% "rules"
  ))

  invisible(x)
}

#' @rdname print.secure_result
#' @export
summary.secure_result <- function(object, ...) {
  print(object)
}
