#' Explain findings
#'
#' Formats scanner findings for console, Markdown, or HTML presentation.
#'
#' @details
#' `explain_findings()` is a presentation helper. It does not rescore or
#' reclassify findings; it formats the finding metadata already present in a
#' [shieldr_report()]. Console output uses severity-colored bullets. Markdown
#' and HTML outputs return character vectors suitable for reports, notebooks,
#' or lightweight dashboards.
#'
#' @param findings A list of finding lists, usually from a `shieldr_report`.
#' @param format One of `"text"`, `"markdown"`, or `"html"`.
#'
#' @return A character vector of formatted finding explanations.
#' @examples
#' report <- scan_prompt("email me at jane@example.com", policy("enterprise_default"))
#' explain_findings(report$findings)
#' @export
explain_findings <- function(findings, format = "text") {
  if (!is.list(findings)) {
    cli::cli_abort("{.arg findings} must be a list.")
  }
  .check_choice(format, "format", c("text", "markdown", "html"))

  if (length(findings) == 0L) {
    return(character())
  }

  lines <- vapply(findings, .finding_text, character(1))
  if (identical(format, "text")) {
    coloured <- mapply(.colour_by_severity, lines, findings, USE.NAMES = FALSE)
    bullets <- stats::setNames(as.character(coloured), rep("*", length(coloured)))
    cli::cli_bullets(bullets)
    return(as.character(lines))
  }

  if (identical(format, "markdown")) {
    out <- unlist(lapply(findings, function(finding) {
      c(
        paste0("## ", finding$rule_id %||% "finding"),
        paste0("- OWASP: ", finding$owasp %||% "unknown"),
        paste0("- Severity: ", finding$severity %||% "unknown"),
        paste0("- Description: ", finding$description %||% "")
      )
    }), use.names = FALSE)
    return(out)
  }

  vapply(findings, function(finding) {
    severity <- finding$severity %||% "unknown"
    paste0(
      "<div class=\"shieldr-finding severity-", .html_escape(severity), "\">",
      "<strong>", .html_escape(finding$rule_id %||% "finding"), "</strong>: ",
      .html_escape(finding$description %||% ""),
      "</div>"
    )
  }, character(1))
}

.finding_text <- function(finding) {
  paste0(
    finding$rule_id %||% "finding",
    " [",
    finding$severity %||% "unknown",
    ", ",
    finding$owasp %||% "unknown",
    "]: ",
    finding$description %||% ""
  )
}

.colour_by_severity <- function(line, finding) {
  severity <- finding$severity %||% "low"
  switch(
    severity,
    critical = cli::col_red(line),
    high = cli::col_yellow(line),
    medium = cli::col_cyan(line),
    low = cli::col_grey(line),
    line
  )
}

.html_escape <- function(x) {
  x <- as.character(x)
  x <- gsub("&", "&amp;", x, fixed = TRUE)
  x <- gsub("<", "&lt;", x, fixed = TRUE)
  x <- gsub(">", "&gt;", x, fixed = TRUE)
  x <- gsub("\"", "&quot;", x, fixed = TRUE)
  x
}
