.stats_begin <- function(show_stats, operation) {
  .validate_flag(show_stats, "show_stats")
  if (!isTRUE(show_stats)) return(NULL)
  state <- new.env(parent = emptyenv())
  state$operation <- operation
  state$started <- proc.time()[["elapsed"]]
  state$network <- "no"
  state$tokens <- NA_real_
  state$token_source <- "unavailable"
  state$upload_bytes <- NA_real_
  state$download_bytes <- NA_real_
  state$network_elapsed_s <- NA_real_
  state
}

.stats_end <- function(state) {
  if (is.null(state)) return(invisible(NULL))
  elapsed_ms <- round((proc.time()[["elapsed"]] - state$started) * 1000, 1)
  tokens <- if (is.finite(state$tokens)) {
    paste0(format(state$tokens, trim = TRUE), " (", state$token_source, ")")
  } else {
    "unavailable"
  }
  fmt_bytes <- function(x) if (is.finite(x)) paste0(format(x, trim = TRUE), " B") else "unavailable"
  fmt_rate <- function(bytes) {
    if (is.finite(bytes) && is.finite(state$network_elapsed_s) && state$network_elapsed_s > 0) {
      paste0(format(round(bytes / state$network_elapsed_s, 1), trim = TRUE), " B/s")
    } else {
      "unavailable"
    }
  }
  cli::cli_inform(c(
    "llmshieldr {.val {state$operation}}: {elapsed_ms} ms",
    "i" = "network: {state$network}; tokens: {tokens}",
    "i" = "upload: {fmt_bytes(state$upload_bytes)} ({fmt_rate(state$upload_bytes)}); download: {fmt_bytes(state$download_bytes)} ({fmt_rate(state$download_bytes)})"
  ))
  invisible(NULL)
}

.stats_text_tokens <- function(state, text) {
  if (!is.null(state)) {
    state$tokens <- .count_tokens(text)
    state$token_source <- "estimate"
  }
  invisible(NULL)
}

.stats_network_from_chat <- function(state, chat) {
  if (is.null(state)) return(invisible(NULL))
  if (is.function(chat)) {
    state$network <- "unknown"
  } else if (is.function(tryCatch(chat$get_provider, error = function(e) NULL))) {
    # Every ellmer provider uses an HTTP transport, including local Ollama.
    state$network <- "yes"
  } else {
    state$network <- "unknown"
  }
  invisible(NULL)
}
