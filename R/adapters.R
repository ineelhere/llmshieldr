#' Optional Presidio detector adapter
#'
#' Creates a guardrail provider that sends scanned text to a caller-managed
#' Presidio Analyzer HTTP service. The adapter is opt-in and transmits content
#' only when a scan using it runs.
#'
#' @param endpoint Presidio analyze endpoint URL.
#' @param language Presidio language code.
#' @param entities Optional requested entity types.
#' @param min_score Minimum Presidio score retained.
#' @param on_error Provider failure behavior.
#' @param timeout_seconds HTTP timeout.
#' @param show_stats Show construction time and available usage metrics.
#'
#' @return A `shieldr_provider` for [scanner_options()].
#' @examples
#' \dontrun{
#' presidio <- presidio_provider("http://127.0.0.1:5002/analyze")
#' }
#' @export
presidio_provider <- function(endpoint,
                              language = "en",
                              entities = NULL,
                              min_score = 0.5,
                              on_error = c("block", "skip"),
                              timeout_seconds = 10,
                              show_stats = FALSE) {
  stats <- .stats_begin(show_stats, "presidio_provider")
  on.exit(.stats_end(stats), add = TRUE)
  .check_string(endpoint, "endpoint")
  .check_string(language, "language")
  if (!is.null(entities) && (!is.character(entities) || anyNA(entities))) cli::cli_abort("{.arg entities} must be a character vector or {.code NULL}.")
  .check_number_between(min_score, "min_score", 0, 1)
  on_error <- match.arg(on_error)
  .validate_optional_positive(timeout_seconds, "timeout_seconds")
  scan <- function(text, stage, metadata) {
    rlang::check_installed("httr2", reason = "Install httr2 to use the Presidio adapter.")
    body <- list(text = text, language = language)
    if (!is.null(entities)) body$entities <- entities
    response <- httr2::request(endpoint) |>
      httr2::req_method("POST") |>
      httr2::req_body_json(body) |>
      httr2::req_timeout(timeout_seconds) |>
      httr2::req_perform()
    parsed <- httr2::resp_body_json(response, simplifyVector = FALSE)
    findings <- lapply(parsed, function(item) {
      score <- suppressWarnings(as.numeric(item$score %||% 0))
      if (!is.finite(score) || score < min_score) return(NULL)
      start <- as.integer(item$start %||% 0L) + 1L
      end <- as.integer(item$end %||% start)
      list(
        rule_id = paste0("llm02.presidio.", tolower(item$entity_type %||% "entity")),
        owasp = "llm02", severity = "high", action = "redact",
        description = paste0("Presidio detected ", item$entity_type %||% "an entity", "."),
        match = substr(text, start, end), start = start, end = end,
        confidence = score, entity_type = item$entity_type %||% "UNKNOWN"
      )
    })
    Filter(Negate(is.null), findings)
  }
  guardrail_provider(
    "presidio/http", scan, version = "api", on_error = on_error,
    timeout_seconds = timeout_seconds
  )
}

#' Optional Gitleaks secret detector adapter
#'
#' Runs a locally installed Gitleaks executable against a temporary text file.
#' No network call is made by this adapter. The temporary file and report are
#' removed on exit.
#'
#' @param command Gitleaks executable path or command name.
#' @param config Optional Gitleaks configuration path.
#' @param on_error Provider failure behavior.
#' @param timeout_seconds Process timeout.
#' @param show_stats Show construction time and available usage metrics.
#'
#' @return A `shieldr_provider` for [scanner_options()].
#' @examples
#' \dontrun{
#' gitleaks <- gitleaks_provider()
#' }
#' @export
gitleaks_provider <- function(command = "gitleaks",
                              config = NULL,
                              on_error = c("block", "skip"),
                              timeout_seconds = 30,
                              show_stats = FALSE) {
  stats <- .stats_begin(show_stats, "gitleaks_provider")
  on.exit(.stats_end(stats), add = TRUE)
  .check_string(command, "command")
  if (!is.null(config)) .check_string(config, "config")
  on_error <- match.arg(on_error)
  .validate_optional_positive(timeout_seconds, "timeout_seconds")
  scan <- function(text, stage, metadata) {
    rlang::check_installed("processx", reason = "Install processx to use the Gitleaks adapter.")
    source_path <- tempfile(fileext = ".txt")
    report_path <- tempfile(fileext = ".json")
    on.exit(unlink(c(source_path, report_path), force = TRUE), add = TRUE)
    writeLines(text, source_path, useBytes = TRUE)
    args <- c("detect", "--no-git", "--source", source_path,
              "--report-format", "json", "--report-path", report_path,
              "--exit-code", "0")
    if (!is.null(config)) args <- c(args, "--config", config)
    processx::run(command, args, timeout = timeout_seconds * 1000,
                  error_on_status = TRUE, echo = FALSE)
    if (!file.exists(report_path) || file.info(report_path)$size == 0L) return(list())
    parsed <- jsonlite::fromJSON(report_path, simplifyVector = FALSE)
    lapply(parsed, function(item) {
      value <- as.character(item$Secret %||% NA_character_)[[1L]]
      location <- if (!is.na(value) && nzchar(value)) regexpr(value, text, fixed = TRUE)[[1L]] else -1L
      list(
        rule_id = paste0("llm02.gitleaks.", gsub("[^A-Za-z0-9_.-]", ".", item$RuleID %||% "secret")),
        owasp = "llm02", severity = "critical", action = "redact",
        description = "Gitleaks detected a credential signature.",
        match = value,
        start = if (location > 0L) location else NA_integer_,
        end = if (location > 0L) location + nchar(value) - 1L else NA_integer_
      )
    })
  }
  guardrail_provider(
    "gitleaks/process", scan, version = "cli", on_error = on_error,
    timeout_seconds = timeout_seconds
  )
}

#' Optional Open Policy Agent adapter
#'
#' Sends metadata and, only when `include_text = TRUE`, text to an OPA Data API
#' decision endpoint. A false decision creates a blocking tool/guardrail finding.
#'
#' @param endpoint Full OPA Data API URL.
#' @param input_builder Optional function receiving `(text, stage, metadata)`.
#' @param include_text Whether raw text is included in the default OPA input.
#' @param on_error Provider failure behavior.
#' @param timeout_seconds HTTP timeout.
#' @param show_stats Show construction time and available usage metrics.
#'
#' @return A `shieldr_provider` for [scanner_options()].
#' @examples
#' \dontrun{
#' opa <- opa_provider("http://127.0.0.1:8181/v1/data/llmshieldr/allow")
#' }
#' @export
opa_provider <- function(endpoint,
                         input_builder = NULL,
                         include_text = FALSE,
                         on_error = c("block", "skip"),
                         timeout_seconds = 10,
                         show_stats = FALSE) {
  stats <- .stats_begin(show_stats, "opa_provider")
  on.exit(.stats_end(stats), add = TRUE)
  .check_string(endpoint, "endpoint")
  if (!is.null(input_builder) && !is.function(input_builder)) cli::cli_abort("{.arg input_builder} must be a function or {.code NULL}.")
  .validate_flag(include_text, "include_text")
  on_error <- match.arg(on_error)
  .validate_optional_positive(timeout_seconds, "timeout_seconds")
  scan <- function(text, stage, metadata) {
    rlang::check_installed("httr2", reason = "Install httr2 to use the OPA adapter.")
    input <- if (!is.null(input_builder)) {
      input_builder(text, stage, metadata)
    } else {
      c(list(stage = stage), metadata, if (isTRUE(include_text)) list(text = text))
    }
    response <- httr2::request(endpoint) |>
      httr2::req_method("POST") |>
      httr2::req_body_json(list(input = input)) |>
      httr2::req_timeout(timeout_seconds) |>
      httr2::req_perform()
    decision <- httr2::resp_body_json(response, simplifyVector = FALSE)$result
    allowed <- if (is.list(decision)) isTRUE(decision$allow %||% decision$allowed) else isTRUE(decision)
    if (allowed) return(list())
    list(list(
      rule_id = "llm03.opa.denied", owasp = "llm03",
      severity = "critical", action = "block",
      description = "Open Policy Agent denied the operation.",
      match = NA_character_, start = NA_integer_, end = NA_integer_
    ))
  }
  guardrail_provider(
    "opa/http", scan, version = "data-api", on_error = on_error,
    timeout_seconds = timeout_seconds
  )
}
