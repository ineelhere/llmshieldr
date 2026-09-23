#' Configure citation and grounding checks
#'
#' Grounding checks validate citation identifiers deterministically and may call
#' an optional validator for unsupported claims or contradictions. Source
#' support is evidence linkage; it does not prove that a source is true.
#'
#' @param require_citations Whether at least one citation is required when
#'   sources are available.
#' @param citation_pattern Regular expression with the citation identifier in
#'   capture group one.
#' @param validator Optional function receiving `(text, source_ids)` and
#'   returning a list with `unsupported_claims` and/or `contradictions`.
#' @param unsupported_action Action for absent or unsupported citations.
#' @param contradiction_action Action for contradiction flags.
#' @param show_stats Show construction time and available usage metrics.
#'
#' @return A `shieldr_grounding_policy` object.
#' @examples
#' grounding <- grounding_policy()
#' scan_grounding("Answer [source:doc-1]", "doc-1", grounding)
#' @export
grounding_policy <- function(require_citations = TRUE,
                             citation_pattern = "\\[source:([A-Za-z0-9_.:-]+)\\]",
                             validator = NULL,
                             unsupported_action = c("block", "redact"),
                             contradiction_action = c("block", "redact"),
                             show_stats = FALSE) {
  stats <- .stats_begin(show_stats, "grounding_policy")
  on.exit(.stats_end(stats), add = TRUE)
  .validate_flag(require_citations, "require_citations")
  .check_string(citation_pattern, "citation_pattern")
  if (!is.null(validator) && !is.function(validator)) cli::cli_abort("{.arg validator} must be a function or {.code NULL}.")
  unsupported_action <- match.arg(unsupported_action)
  contradiction_action <- match.arg(contradiction_action)
  structure(
    list(
      require_citations = require_citations,
      citation_pattern = citation_pattern,
      validator = validator,
      unsupported_action = unsupported_action,
      contradiction_action = contradiction_action
    ),
    class = "shieldr_grounding_policy"
  )
}

#' Check output citations against admitted sources
#'
#' @param text Model output.
#' @param source_ids Provenance identifiers for admitted sources.
#' @param policy Grounding policy from [grounding_policy()].
#' @param show_stats Show execution statistics as messages.
#'
#' @return A `shieldr_report`.
#' @examples
#' scan_grounding("Claim [source:missing]", "doc-1")$action
#' @export
scan_grounding <- function(text,
                           source_ids,
                           policy = grounding_policy(),
                           show_stats = FALSE) {
  stats <- .stats_begin(show_stats, "scan_grounding")
  on.exit(.stats_end(stats), add = TRUE)
  .stats_text_tokens(stats, text)
  .check_string(text, "text", allow_empty = TRUE)
  if (!is.character(source_ids) || anyNA(source_ids)) cli::cli_abort("{.arg source_ids} must be a character vector without missing values.")
  .validate_grounding_policy(policy)
  citations <- .extract_citation_ids(text, policy$citation_pattern)
  findings <- list()
  add <- function(id, description, action) {
    findings[[length(findings) + 1L]] <<- .synthetic_finding(
      id, "llm07", if (identical(action, "block")) "critical" else "high",
      description, action = action
    )
  }
  if (isTRUE(policy$require_citations) && length(source_ids) > 0L && length(citations) == 0L) {
    add("llm07.grounding.missing_citation", "Output contains no citation to an admitted source.", policy$unsupported_action)
  }
  unknown <- setdiff(citations, source_ids)
  if (length(unknown) > 0L) {
    add("llm07.grounding.fabricated_citation", "Output cites a source identifier that was not admitted.", policy$unsupported_action)
  }
  if (!is.null(policy$validator)) {
    validation <- tryCatch(policy$validator(text, source_ids), error = identity)
    if (inherits(validation, "error")) {
      add("llm07.grounding.validator_failure", "Required grounding validator failed.", "block")
    } else if (is.list(validation)) {
      if (length(validation$unsupported_claims %||% list()) > 0L) {
        add("llm07.grounding.unsupported_claim", "Grounding validator flagged unsupported claims.", policy$unsupported_action)
      }
      if (length(validation$contradictions %||% list()) > 0L) {
        add("llm07.grounding.contradiction", "Grounding validator flagged a contradiction with supplied sources.", policy$contradiction_action)
      }
    } else {
      cli::cli_abort("Grounding validator must return a list.")
    }
  }
  risk <- .score_findings(findings)
  policy_obj <- shieldr_policy("grounding", list(), list(redact_at = 0.3, block_at = 0.7))
  shieldr_report(
    action = .resolve_action(risk, findings, policy_obj),
    text_clean = text,
    findings = findings,
    risk_score = risk,
    policy = "grounding",
    checks = "grounding",
    metadata = .report_metadata(
      stage = "grounding", source_ids = source_ids,
      cited_source_ids = citations, unknown_source_ids = unknown
    )
  )
}

.validate_grounding_policy <- function(x, allow_null = FALSE) {
  if (is.null(x) && isTRUE(allow_null)) return(invisible(TRUE))
  if (!inherits(x, "shieldr_grounding_policy")) cli::cli_abort("{.arg grounding} must be created by {.fn grounding_policy}.")
  invisible(TRUE)
}

.extract_citation_ids <- function(text, pattern) {
  hits <- gregexpr(pattern, text, perl = TRUE)[[1L]]
  if (length(hits) == 0L || identical(hits[[1L]], -1L)) return(character())
  values <- regmatches(text, list(hits))[[1L]]
  unique(vapply(values, function(value) {
    captured <- sub(pattern, "\\1", value, perl = TRUE)
    if (identical(captured, value)) NA_character_ else captured
  }, character(1)) |> .compact_chr())
}

.merge_reports <- function(primary, extra, policy) {
  findings <- .dedupe_findings(c(primary$findings, extra$findings))
  primary$findings <- findings
  primary$risk_score <- .score_findings(findings)
  policy_obj <- .as_policy(policy)
  if (identical(primary$metadata$stage, "output")) policy_obj <- .output_policy(policy_obj)
  primary$action <- .resolve_action(primary$risk_score, findings, policy_obj)
  primary$metadata$grounding <- extra$metadata
  primary
}
