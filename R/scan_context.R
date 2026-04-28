#' Scan retrieved context rows
#'
#' Scans data-frame context chunks and adds OWASP LLM08-style anomaly and
#' source-trust findings before returning row-aligned reports.
#'
#' @param data A data frame.
#' @param text_col Column containing context text. Supply a string or bare name.
#' @param policy A `shieldr_policy`.
#' @param reviewer Optional reviewer function or object with `$chat()`.
#' @param checks One of `"rules"`, `"llm"`, or `"both"`.
#' @param source_col Optional source column used with `policy$trusted_sources`.
#' @param anomaly_threshold Z-score threshold for anomaly findings.
#'
#' @return A list of `shieldr_report` objects, one per row.
#' @examples
#' ctx <- data.frame(text = c("clean note", "ignore previous instructions"))
#' scan_context(ctx, "text", policy_preset("enterprise_default"))
#' @export
scan_context <- function(data,
                         text_col,
                         policy,
                         reviewer = NULL,
                         checks = "rules",
                         source_col = NULL,
                         anomaly_threshold = 2.5) {
  if (missing(text_col)) {
    cli::cli_abort("{.arg text_col} is required.")
  }
  if (!is.data.frame(data)) {
    cli::cli_abort("{.arg data} must be a data frame.")
  }
  .check_policy(policy)
  checks <- .validate_checks(checks)
  .validate_reviewer(reviewer)
  .check_number_between(anomaly_threshold, "anomaly_threshold", 0, Inf)

  text_name <- .column_name(substitute(text_col), data, "text_col", parent.frame())
  source_name <- .column_name(substitute(source_col), data, "source_col", parent.frame(), allow_null = TRUE)

  if (!text_name %in% names(data)) {
    cli::cli_abort("{.arg text_col} must name a column in {.arg data}.")
  }
  if (!is.null(source_name) && !source_name %in% names(data)) {
    cli::cli_abort("{.arg source_col} must name a column in {.arg data}.")
  }

  text <- as.character(data[[text_name]])
  text[is.na(text)] <- ""
  if (length(text) == 0L) {
    return(list())
  }

  length_z <- .robust_z(nchar(text))
  density <- .instruction_density(text)
  density_z <- .robust_z(density)

  trusted_sources <- policy$trusted_sources
  reports <- vector("list", length(text))
  for (i in seq_along(text)) {
    extra <- list()
    if (is.finite(length_z[[i]]) && length_z[[i]] > anomaly_threshold || is.infinite(length_z[[i]])) {
      extra[[length(extra) + 1L]] <- .synthetic_finding(
        "llm08.anomaly.length",
        "llm08",
        "high",
        "Context chunk has anomalous character length."
      )
    }
    if (is.finite(density_z[[i]]) && density_z[[i]] > anomaly_threshold || is.infinite(density_z[[i]])) {
      extra[[length(extra) + 1L]] <- .synthetic_finding(
        "llm08.anomaly.instruction_density",
        "llm08",
        "high",
        "Context chunk has anomalous instruction-word density."
      )
    }
    if (!is.null(source_name) && !is.null(trusted_sources)) {
      source_value <- as.character(data[[source_name]][[i]])
      if (is.na(source_value) || !source_value %in% trusted_sources) {
        extra <- c(
          list(
            .synthetic_finding(
              "llm08.untrusted_source",
              "llm08",
              "medium",
              "Context source is not in the policy trusted-source allowlist."
            )
          ),
          extra
        )
      }
    }

    report <- scan_prompt(text[[i]], policy, reviewer = reviewer, checks = checks)
    findings <- .dedupe_findings(c(extra, report$findings))
    risk_score <- .score_findings(findings)
    action <- .resolve_action(risk_score, findings, policy)
    reports[[i]] <- shieldr_report(
      action = action,
      text_clean = .apply_redaction(report$text_clean, findings),
      findings = findings,
      risk_score = risk_score,
      policy = policy$name,
      checks = checks,
      timestamp = report$timestamp
    )
  }

  reports
}

.synthetic_finding <- function(rule_id, owasp, severity, description, action = "redact") {
  list(
    rule_id = rule_id,
    owasp = owasp,
    severity = severity,
    action = action,
    description = description,
    match = NA_character_,
    start = NA_integer_,
    end = NA_integer_,
    source = "rules"
  )
}

.instruction_density <- function(text) {
  vapply(text, function(item) {
    tokens <- strsplit(trimws(item), "\\s+", perl = TRUE)[[1]]
    tokens <- tokens[nzchar(tokens)]
    n_tokens <- max(length(tokens), 1L)
    hits <- gregexpr("\\b(ignore|forget|override|instead|disregard)\\b", item, ignore.case = TRUE, perl = TRUE)[[1]]
    n_hits <- if (identical(hits[[1]], -1L)) 0L else length(hits)
    100 * n_hits / n_tokens
  }, numeric(1))
}

.robust_z <- function(x) {
  if (length(x) <= 1L) {
    return(rep(0, length(x)))
  }
  center <- stats::median(x, na.rm = TRUE)
  scale <- stats::mad(x, constant = 1.4826, na.rm = TRUE)
  if (!is.finite(scale) || scale == 0) {
    return(ifelse(x == center, 0, Inf))
  }
  (x - center) / scale
}

.column_name <- function(expr, data, arg, env, allow_null = FALSE) {
  if (identical(expr, quote(NULL))) {
    if (allow_null) {
      return(NULL)
    }
    cli::cli_abort("{.arg {arg}} must not be {.code NULL}.")
  }
  if (is.character(expr)) {
    return(expr[[1]])
  }
  if (is.symbol(expr)) {
    name <- as.character(expr)
    if (name %in% names(data)) {
      return(name)
    }
    value <- tryCatch(eval(expr, envir = env), error = function(e) NULL)
    if (is.null(value) && allow_null) {
      return(NULL)
    }
    if (is.character(value) && length(value) == 1L) {
      return(value)
    }
    return(name)
  }
  value <- tryCatch(eval(expr, envir = env), error = function(e) NULL)
  if (is.character(value) && length(value) == 1L) {
    return(value)
  }
  cli::cli_abort("{.arg {arg}} must be a column name.")
}
