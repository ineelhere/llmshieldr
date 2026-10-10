#' OWASP LLM Top 10 2026 migration crosswalk
#'
#' Returns edition-qualified 2026 categories and predecessor labels used to
#' migrate dashboards without changing stable internal rule IDs. A category
#' mapping describes relevance; it is not a claim of full mitigation.
#'
#' @param show_stats Show lookup time and available usage metrics.
#'
#' @return A data frame with 2026 IDs, names, predecessor IDs, and package
#'   evidence level.
#' @examples
#' owasp_crosswalk()
#' @export
owasp_crosswalk <- function(show_stats = FALSE) {
  stats <- .stats_begin(show_stats, "owasp_crosswalk")
  on.exit(.stats_end(stats), add = TRUE)
  data.frame(
    id_2026 = sprintf("LLM%02d:2026", 1:10),
    name_2026 = c(
      "Prompt Injection",
      "Sensitive Information Disclosure",
      "Excessive Agency",
      "Supply Chain",
      "Data and Model Poisoning",
      "Unbounded Consumption",
      "Misinformation",
      "Hidden Context Exposure",
      "Vector and Embedding Weaknesses",
      "Improper Output Handling"
    ),
    predecessor_2025 = c(
      "LLM01:2025", "LLM02:2025", "LLM06:2025", "LLM03:2025",
      "LLM04:2025", "LLM10:2025", "LLM09:2025", "LLM07:2025",
      "LLM08:2025", "LLM05:2025"
    ),
    package_evidence = c(
      "detector and boundary controls", "detector and redaction controls",
      "agency and tool controls", "metadata only",
      "context provenance signals", "quota and limit controls",
      "claim and grounding signals", "hidden-context detectors",
      "context admission controls", "contract and URL controls"
    ),
    stringsAsFactors = FALSE
  )
}
