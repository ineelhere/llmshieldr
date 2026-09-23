#' Scan streamed output chunks with rolling context
#'
#' `scan_stream()` scans character chunks as they arrive from a streaming model
#' API. Each scan uses the current chunk plus a configurable overlap from the
#' previous text so rules can catch phrases split across chunk boundaries. The
#' returned `text` is scanned again as a whole and contains only releasable
#' text: a blocked result has an empty string and a redacted result contains
#' the cleaned text. This helper accepts chunks after they have been received;
#' callers must not forward raw chunks before the final decision.
#'
#' @details
#' This helper is intentionally transport-agnostic: pass the text chunks you
#' receive from an SDK, callback, or websocket handler. It returns per-window
#' reports and a combined action. If `on_block = "stop"`, the function aborts
#' as soon as a window resolves to `block`; use `on_block = "return"` when you
#' want a full report object instead.
#'
#' `chunk_size` is used only when `chunks` is a single long string. Character
#' vectors with more than one element are treated as already chunked.
#'
#' @param chunks Character vector of streamed text chunks, or one long string.
#' @param policy A `shieldr_policy` or built-in policy name.
#' @param reviewer Optional reviewer function or object with `$chat()`.
#' @param checks One of `"rules"`, `"nlp"`, `"llm"`, or `"both"`.
#' @param chunk_size Maximum size used to split a single long string.
#' @param overlap Number of trailing characters from prior output to include
#'   when scanning the next chunk.
#' @param on_block One of `"stop"` or `"return"`.
#' @param redaction Optional redaction strategy from [redaction_strategy()].
#' @param scanners Optional scanner configuration from [scanner_options()].
#' @param show_tokens Whether to attach token counts when `ellmer` is available.
#' @param show_stats Show execution statistics as messages.
#' @param report_content `"metadata"` (default) strips text and evidence from
#'   per-window reports; `"full"` retains them in memory.
#'
#' @return A `shieldr_stream_result` list with `action`, `text`, and `reports`.
#' @examples
#' scan_stream(
#'   c("I will now ", "delete the records."),
#'   on_block = "return"
#' )
#' @export
scan_stream <- function(chunks,
                        policy = "enterprise_default",
                        reviewer = NULL,
                        checks = "rules",
                        chunk_size = 1000L,
                        overlap = 200L,
                        on_block = c("stop", "return"),
                        redaction = NULL,
                        scanners = scanner_options(),
                        show_tokens = FALSE,
                        show_stats = FALSE,
                        report_content = c("metadata", "full")) {
  stats <- .stats_begin(show_stats, "scan_stream")
  on.exit(.stats_end(stats), add = TRUE)
  report_content <- match.arg(report_content)
  if (!is.character(chunks)) {
    cli::cli_abort("{.arg chunks} must be a character vector.")
  }
  .validate_nullable_limit(chunk_size, "chunk_size", allow_null = FALSE)
  .validate_nullable_limit(overlap, "overlap", allow_null = FALSE)
  on_block <- match.arg(on_block)

  chunks <- chunks[!is.na(chunks)]
  .stats_text_tokens(stats, paste(chunks, collapse = ""))
  .stats_track_reviewer(stats, reviewer, checks)
  if (length(chunks) == 1L && nchar(chunks, type = "chars") > chunk_size) {
    chunks <- .split_stream_text(chunks, as.integer(chunk_size))
  }
  if (length(chunks) == 0L) {
    return(structure(
      list(action = "allow", text = "", reports = list()),
      class = "shieldr_stream_result"
    ))
  }

  reports <- vector("list", length(chunks))
  accumulated <- ""
  for (i in seq_along(chunks)) {
    prefix <- if (nzchar(accumulated) && overlap > 0L) {
      start <- max(1L, nchar(accumulated, type = "chars") - as.integer(overlap) + 1L)
      substr(accumulated, start, nchar(accumulated, type = "chars"))
    } else {
      ""
    }
    window <- paste0(prefix, chunks[[i]])
    report <- scan_output(
      window,
      policy = policy,
      reviewer = reviewer,
      checks = checks,
      redaction = redaction,
      scanners = scanners,
      show_tokens = show_tokens
    )
    report$metadata <- utils::modifyList(
      report$metadata %||% list(),
      .report_metadata(stage = "stream", chunk_index = i, overlap = overlap)
    )
    reports[[i]] <- report
    accumulated <- paste0(accumulated, chunks[[i]])

    if (identical(report$action, "block") && identical(on_block, "stop")) {
      cli::cli_abort("Streaming output blocked by llmshieldr at chunk {i}.")
    }
  }

  actions <- vapply(reports, function(report) report$action, character(1))
  final_report <- scan_output(
    accumulated,
    policy = policy,
    reviewer = reviewer,
    checks = checks,
    redaction = redaction,
    scanners = scanners,
    show_tokens = show_tokens
  )
  action <- .combine_actions(c(actions, final_report$action))
  if (identical(action, "block") && identical(on_block, "stop")) {
    cli::cli_abort("Streaming output blocked by llmshieldr after final scan.")
  }
  safe_text <- if (identical(action, "block")) {
    ""
  } else if (identical(action, "redact") && identical(final_report$text_clean, accumulated)) {
    # A window identified content that a full scan did not clean. Release none.
    ""
  } else {
    final_report$text_clean
  }
  structure(
    list(
      action = action,
      text = safe_text,
      reports = if (identical(report_content, "metadata")) {
        lapply(reports, .audit_metadata_report)
      } else {
        reports
      }
    ),
    class = "shieldr_stream_result"
  )
}

.split_stream_text <- function(text, chunk_size) {
  starts <- seq.int(1L, nchar(text, type = "chars"), by = chunk_size)
  vapply(starts, function(start) {
    substr(text, start, min(nchar(text, type = "chars"), start + chunk_size - 1L))
  }, character(1))
}

#' Create a stateful safe-release stream guard
#'
#' Buffers provider chunks and releases text only after [scan_stream()] has made
#' a final decision over the complete response. This conservative contract
#' prevents split payloads from reaching the consumer and makes cancellation
#' explicit. It trades token-by-token display for a release guarantee; callers
#' must send raw provider chunks only to `$push()`.
#'
#' @param emit Function receiving the final cleaned text after an allow/redact
#'   decision.
#' @param cancel Optional function called when the guard blocks or is cancelled.
#' @inheritParams scan_stream
#' @param show_stats Show construction time and available usage metrics.
#'
#' @return A `shieldr_stream_guard` environment with `$push(chunk)`, `$finish()`,
#'   `$cancel()`, and `$status()` methods. Each method accepts `show_stats`.
#' @examples
#' released <- character()
#' guard <- stream_guard(function(text) released <<- c(released, text))
#' guard$push("Contact ")
#' guard$push("a@example.com")
#' result <- guard$finish()
#' @export
stream_guard <- function(emit,
                         cancel = NULL,
                         policy = "enterprise_default",
                         reviewer = NULL,
                         checks = "rules",
                         overlap = 200L,
                         redaction = NULL,
                         scanners = scanner_options(),
                         show_tokens = FALSE,
                         show_stats = FALSE) {
  stats <- .stats_begin(show_stats, "stream_guard")
  on.exit(.stats_end(stats), add = TRUE)
  if (!is.function(emit)) cli::cli_abort("{.arg emit} must be a function.")
  if (!is.null(cancel) && !is.function(cancel)) cli::cli_abort("{.arg cancel} must be a function or {.code NULL}.")
  .validate_nullable_limit(overlap, "overlap", allow_null = FALSE)
  state <- new.env(parent = emptyenv())
  state$chunks <- character()
  state$finished <- FALSE
  state$cancelled <- FALSE
  state$result <- NULL

  state$push <- function(chunk, show_stats = FALSE) {
    method_stats <- .stats_begin(show_stats, "stream_guard$push")
    on.exit(.stats_end(method_stats), add = TRUE)
    if (state$finished || state$cancelled) cli::cli_abort("The stream guard is already closed.")
    .check_string(chunk, "chunk", allow_empty = TRUE)
    .stats_text_tokens(method_stats, chunk)
    state$chunks <- c(state$chunks, chunk)
    invisible(NULL)
  }
  state$finish <- function(show_stats = FALSE) {
    method_stats <- .stats_begin(show_stats, "stream_guard$finish")
    on.exit(.stats_end(method_stats), add = TRUE)
    if (state$cancelled) cli::cli_abort("The stream guard was cancelled.")
    if (state$finished) return(state$result)
    state$result <- scan_stream(
      state$chunks, policy = policy, reviewer = reviewer, checks = checks,
      overlap = overlap, on_block = "return", redaction = redaction,
      scanners = scanners, show_tokens = show_tokens
    )
    state$finished <- TRUE
    if (identical(state$result$action, "block")) {
      state$cancelled <- TRUE
      if (!is.null(cancel)) cancel()
    } else {
      emit(state$result$text)
    }
    state$result
  }
  state$cancel <- function(show_stats = FALSE) {
    method_stats <- .stats_begin(show_stats, "stream_guard$cancel")
    on.exit(.stats_end(method_stats), add = TRUE)
    if (!state$cancelled) {
      state$cancelled <- TRUE
      if (!is.null(cancel)) cancel()
    }
    invisible(NULL)
  }
  state$status <- function(show_stats = FALSE) {
    method_stats <- .stats_begin(show_stats, "stream_guard$status")
    on.exit(.stats_end(method_stats), add = TRUE)
    list(
      finished = state$finished,
      cancelled = state$cancelled,
      chunks_received = length(state$chunks),
      action = state$result$action %||% NULL
    )
  }
  class(state) <- c("shieldr_stream_guard", class(state))
  state
}
