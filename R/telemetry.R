#' Configure privacy-safe guardrail telemetry
#'
#' A telemetry exporter receives one structured metadata event at a time. Event
#' payloads contain decision IDs, stages, actions, timing, counts, and status;
#' they do not contain prompt, output, finding matches, or reviewer excerpts.
#' The callback can translate these events to OpenTelemetry spans or another
#' observability backend outside the core package.
#'
#' @param exporter Function receiving one event list.
#' @param service_name Service identifier added to every event.
#' @param attributes Additional scalar deployment attributes.
#' @param on_error Whether exporter failure warns and continues or stops.
#' @param show_stats Show construction time and available usage metrics.
#'
#' @return A `shieldr_telemetry` object for [secure_chat()].
#' @examples
#' events <- list()
#' telemetry <- telemetry_options(function(event) {
#'   events[[length(events) + 1L]] <<- event
#' })
#' @export
telemetry_options <- function(exporter,
                              service_name = "llmshieldr",
                              attributes = list(),
                              on_error = c("warn", "stop"),
                              show_stats = FALSE) {
  stats <- .stats_begin(show_stats, "telemetry_options")
  on.exit(.stats_end(stats), add = TRUE)
  if (!is.function(exporter)) cli::cli_abort("{.arg exporter} must be a function.")
  .check_string(service_name, "service_name")
  if (!is.list(attributes)) cli::cli_abort("{.arg attributes} must be a list.")
  scalar <- vapply(attributes, function(x) is.atomic(x) && length(x) == 1L, logical(1))
  if (length(scalar) > 0L && any(!scalar)) cli::cli_abort("Every telemetry attribute must be a scalar atomic value.")
  on_error <- match.arg(on_error)
  structure(
    list(exporter = exporter, service_name = service_name, attributes = attributes, on_error = on_error),
    class = "shieldr_telemetry"
  )
}

.validate_telemetry <- function(x, allow_null = FALSE) {
  if (is.null(x) && isTRUE(allow_null)) return(invisible(TRUE))
  if (!inherits(x, "shieldr_telemetry")) cli::cli_abort("{.arg telemetry} must be created by {.fn telemetry_options}.")
  invisible(TRUE)
}

.emit_telemetry <- function(telemetry, decision_id, stage, event,
                            report = NULL, elapsed_ms = NULL, details = list()) {
  if (is.null(telemetry)) return(invisible(NULL))
  payload <- c(
    list(
      schema_version = "1.0",
      decision_id = decision_id,
      timestamp = .now_iso(),
      service_name = telemetry$service_name,
      stage = stage,
      event = event,
      action = if (inherits(report, "shieldr_report")) report$action else NULL,
      risk_score = if (inherits(report, "shieldr_report")) report$risk_score else NULL,
      finding_count = if (inherits(report, "shieldr_report")) length(report$findings) else NULL,
      review_status = if (inherits(report, "shieldr_report")) report$metadata$review_status %||% NULL else NULL,
      elapsed_ms = elapsed_ms
    ),
    telemetry$attributes,
    details
  )
  payload <- payload[!vapply(payload, is.null, logical(1))]
  error <- tryCatch({ telemetry$exporter(payload); NULL }, error = identity)
  if (!is.null(error)) {
    if (identical(telemetry$on_error, "stop")) stop(error)
    cli::cli_warn("Telemetry exporter failed; the guardrail decision continues without that event.")
  }
  invisible(payload)
}
