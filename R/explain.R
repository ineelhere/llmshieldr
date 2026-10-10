#' Explain findings
#'
#' Formats scanner findings for console, Markdown, or HTML presentation.
#'
#' @details
#' `explain_findings()` is a presentation helper. It does not rescore or
#' reclassify findings; it formats the finding metadata already present in a
#' [shieldr_report()]. Console output uses severity-colored bullets. Markdown
#' and HTML outputs return character vectors suitable for reports, notebooks,
#' or lightweight dashboards. Text output prints one set of bullets and returns
#' the character vector invisibly, so an interactive call does not repeat it.
#'
#' @param findings A `shieldr_report` or a list of its finding lists.
#' @param format One of `"text"`, `"markdown"`, or `"html"`.
#' @param show_stats Show formatting time and available usage metrics.
#'
#' @return A character vector of formatted finding explanations. For
#'   `format = "text"`, the value is returned invisibly after printing bullets.
#' @examples
#' report <- scan_prompt("email me at neel@example.com", policy("enterprise_default"))
#' explain_findings(report)
#' @export
explain_findings <- function(findings, format = "text", show_stats = FALSE) {
  stats <- .stats_begin(show_stats, "explain_findings")
  on.exit(.stats_end(stats), add = TRUE)
  if (inherits(findings, "shieldr_report")) {
    findings <- findings$findings
  }
  if (!is.list(findings) ||
      !all(vapply(findings, is.list, logical(1)))) {
    cli::cli_abort("{.arg findings} must be a {.cls shieldr_report} or a list of finding lists.")
  }
  .check_choice(format, "format", c("text", "markdown", "html"))

  if (length(findings) == 0L) {
    if (identical(format, "text")) return(invisible(character()))
    return(character())
  }

  lines <- vapply(findings, .finding_text, character(1))
  if (identical(format, "text")) {
    coloured <- mapply(.colour_by_severity, lines, findings, USE.NAMES = FALSE)
    bullets <- stats::setNames(as.character(coloured), rep("*", length(coloured)))
    cli::cli_bullets(bullets)
    return(invisible(as.character(lines)))
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
    severity <- .html_escape(finding$severity %||% "unknown")
    rule_id <- .html_escape(finding$rule_id %||% "finding")
    description <- .html_escape(finding$description %||% "")
    match <- finding$match %||% NA_character_
    match_html <- if (!is.na(match) && nzchar(match)) {
      paste0("<span class=\"shieldr-match\">", .html_escape(match), "</span>")
    } else {
      ""
    }
    paste0(
      "<div class=\"shieldr-finding severity-", severity, "\">",
      "<strong>", rule_id, "</strong>: ",
      description,
      match_html,
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
  if (requireNamespace("htmltools", quietly = TRUE)) {
    return(as.character(htmltools::htmlEscape(x)))
  }
  gsub("[<>&\"']", "", x)
}
