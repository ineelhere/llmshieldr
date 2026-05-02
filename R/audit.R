#' Write an audit log
#'
#' Persists a `shieldr_audit` object as JSON Lines, CSV, or RDS for operational
#' auditability across LLM workflows.
#'
#' @details
#' JSON Lines is the preferred append-only format for production logs because
#' each call writes one complete audit object as one line. CSV flattens findings
#' into one row per finding, which is convenient for spreadsheets and simple
#' dashboards but loses some nested structure. RDS preserves the R object
#' exactly and overwrites the target path.
#'
#' Audit logs may contain sensitive source text, raw model output, or redacted
#' findings depending on the workflow. Treat audit paths as sensitive storage in
#' regulated or internal environments.
#'
#' @param audit A `shieldr_audit` object.
#' @param path Output file path.
#' @param format One of `"jsonl"`, `"csv"`, or `"rds"`.
#'
#' @return The path, invisibly.
#' @examples
#' audit <- shieldr_audit(NULL, NULL, NULL, "hello", NULL, 0, 1L, "allow")
#' path <- tempfile(fileext = ".jsonl")
#' write_audit_log(audit, path)
#' @export
write_audit_log <- function(audit, path, format = "jsonl") {
  if (!inherits(audit, "shieldr_audit")) {
    cli::cli_abort("{.arg audit} must be a {.cls shieldr_audit}.")
  }
  .check_string(path, "path")
  .check_choice(format, "format", c("jsonl", "csv", "rds"))

  dir <- dirname(path)
  if (!dir.exists(dir)) {
    dir.create(dir, recursive = TRUE, showWarnings = FALSE)
  }

  switch(
    format,
    jsonl = {
      json <- jsonlite::toJSON(.strip_classes(audit), auto_unbox = TRUE, null = "null")
      con <- file(path, open = "a", encoding = "UTF-8")
      on.exit(close(con), add = TRUE)
      writeLines(json, con = con, sep = "\n", useBytes = TRUE)
    },
    csv = {
      rows <- .flatten_audit_findings(audit)
      exists <- file.exists(path)
      utils::write.table(
        rows,
        file = path,
        sep = ",",
        row.names = FALSE,
        col.names = !exists,
        append = exists,
        qmethod = "double"
      )
    },
    rds = {
      if (file.exists(path)) {
        cli::cli_warn("Overwriting existing RDS audit log at {.path {path}}.")
      }
      saveRDS(audit, path)
    }
  )

  invisible(path)
}

.flatten_audit_findings <- function(audit) {
  reports <- .collect_reports(list(
    input = audit$input_report,
    output = audit$output_report,
    context = audit$context_reports
  ))
  rows <- list()
  for (stage in c("input", "output", "context")) {
    stage_reports <- switch(
      stage,
      input = if (inherits(audit$input_report, "shieldr_report")) list(audit$input_report) else list(),
      output = if (inherits(audit$output_report, "shieldr_report")) list(audit$output_report) else list(),
      context = audit$context_reports %||% list()
    )
    for (report_index in seq_along(stage_reports)) {
      report <- stage_reports[[report_index]]
      if (!inherits(report, "shieldr_report")) {
        next
      }
      for (finding in report$findings) {
        rows[[length(rows) + 1L]] <- data.frame(
          stage = stage,
          context_row_index = if (identical(stage, "context")) report_index else NA_integer_,
          report_index = report_index,
          action = report$action,
          risk_score = report$risk_score,
          rule_id = finding$rule_id %||% NA_character_,
          owasp = finding$owasp %||% NA_character_,
          severity = finding$severity %||% NA_character_,
          description = finding$description %||% NA_character_,
          source = finding$source %||% NA_character_,
          stringsAsFactors = FALSE
        )
      }
    }
  }
  if (length(rows) == 0L) {
    return(data.frame(
      stage = character(),
      context_row_index = integer(),
      report_index = integer(),
      action = character(),
      risk_score = numeric(),
      rule_id = character(),
      owasp = character(),
      severity = character(),
      description = character(),
      source = character(),
      stringsAsFactors = FALSE
    ))
  }
  do.call(rbind, rows)
}

.strip_classes <- function(x) {
  if (is.environment(x)) {
    return("<environment>")
  }
  if (is.list(x)) {
    x <- lapply(unclass(x), .strip_classes)
    return(x)
  }
  x
}
