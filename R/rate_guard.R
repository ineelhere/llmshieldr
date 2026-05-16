#' Create or check a rate guard
#'
#' Rate guards are explicit stateful environments used to cap token and request
#' budgets for LLM workflows. Resource exhaustion is covered by OWASP LLM10; see
#' <https://genai.owasp.org/llm-top-10/>.
#'
#' @details
#' Calling `rate_guard()` with limits creates a new `shieldr_rate_guard`
#' environment. The environment stores counters for the current window and
#' exposes two methods:
#'
#' - `$usage()`: returns current counters and configured limits.
#' - `$reserve(tokens, requests)`: atomically checks projected usage and then
#'   increments counters when the reservation stays within limits.
#' - `$update(tokens, requests)`: backward-compatible alias for `$reserve()`.
#' - `$rollback(tokens, requests)`: subtracts a previous reservation after a
#'   guarded operation fails before completion.
#'
#' Calling `rate_guard(guard)` checks an existing environment and returns
#' `TRUE` if all counters are within limits. Reservation methods fail before
#' projected usage exceeds the configured token or request limit. Limits set to
#' `NULL` are disabled for that dimension.
#'
#' Windows reset automatically when `window_seconds` has elapsed. This object
#' is intentionally stateful; it is the one place where llmshieldr expects
#' mutable state, because rate limiting is inherently session-based.
#'
#' @section Concurrency:
#' The rate guard is not safe for concurrent use by default. Parallel or async R
#' code (`future`, `parallel`, `callr`) that shares a single guard environment
#' will produce inaccurate counts. Use `concurrent = TRUE` and install the
#' `filelock` package to make each `$usage()`, `$reserve()`, `$update()`, and
#' `$rollback()` call acquire a file-based lock within a single machine.
#' Cross-machine coordination is not supported.
#'
#' @section Pre-call Reservation:
#' With `strict = TRUE`, [secure_chat()] reserves an estimated prompt token cost
#' and one request before the model call, then records only the positive
#' difference between the actual token estimate and the reserved amount after
#' the call. If the chat call or output scan fails, the pre-call reservation is
#' rolled back. This makes shared guards more useful under bursty load, but
#' estimated tokens may differ from actual usage. Strict mode is recommended
#' when multiple callers share one guard.
#'
#' @param max_tokens Maximum tokens per window, `NULL`, or an existing
#'   `shieldr_rate_guard` when checking a guard with `rate_guard(guard)`.
#' @param max_requests Maximum requests per window, or `NULL`.
#' @param window_seconds Window length in seconds.
#' @param strict Whether [secure_chat()] should reserve estimated prompt tokens
#'   before calling the model.
#' @param concurrent Whether to protect `$usage()` and `$update()` with a
#'   file-based lock from the suggested `filelock` package.
#'
#' @return When creating a guard, a `shieldr_rate_guard` environment. When
#'   checking a guard, `TRUE` if usage is within limits.
#' @examples
#' guard <- rate_guard(max_tokens = 100)
#' guard$reserve(tokens = 10)
#' rate_guard(guard)
#' @export
rate_guard <- function(max_tokens = NULL,
                       max_requests = NULL,
                       window_seconds = 3600L,
                       strict = FALSE,
                       concurrent = FALSE) {
  if (inherits(max_tokens, "shieldr_rate_guard")) {
    session <- max_tokens
    usage <- session$usage()

    if (!is.null(usage$max_tokens) && usage$tokens_used > usage$max_tokens) {
      cli::cli_abort("LLM10 rate guard exceeded: token usage {usage$tokens_used} is above limit {usage$max_tokens}.")
    }
    if (!is.null(usage$max_requests) && usage$requests_made > usage$max_requests) {
      cli::cli_abort("LLM10 rate guard exceeded: request count {usage$requests_made} is above limit {usage$max_requests}.")
    }

    return(TRUE)
  }

  .validate_nullable_limit(max_tokens, "max_tokens")
  .validate_nullable_limit(max_requests, "max_requests")
  .validate_nullable_limit(window_seconds, "window_seconds", allow_null = FALSE)
  .validate_flag(strict, "strict")
  .validate_flag(concurrent, "concurrent")
  if (isTRUE(concurrent)) {
    .check_filelock()
  }

  env <- new.env(parent = emptyenv())
  env$.tokens_used <- 0
  env$.requests_made <- 0L
  env$.window_start <- Sys.time()
  env$.max_tokens <- max_tokens
  env$.max_requests <- max_requests
  env$.window_seconds <- as.integer(window_seconds)
  env$.strict <- isTRUE(strict)
  env$.concurrent <- isTRUE(concurrent)
  env$.lock_path <- if (isTRUE(concurrent)) tempfile(fileext = ".lock") else NULL

  env$usage <- function() {
    lock <- .rate_guard_lock(env)
    on.exit(.rate_guard_unlock(lock), add = TRUE)
    .rate_guard_reset_if_expired(env)
    .rate_guard_usage_snapshot(env)
  }

  env$update <- function(tokens, requests = 1L) {
    env$reserve(tokens = tokens, requests = requests)
  }

  env$reserve <- function(tokens = 0, requests = 1L) {
    .validate_nullable_limit(tokens, "tokens", allow_null = FALSE)
    .validate_nullable_limit(requests, "requests", allow_null = FALSE)
    lock <- .rate_guard_lock(env)
    on.exit(.rate_guard_unlock(lock), add = TRUE)
    .rate_guard_reset_if_expired(env)
    .rate_guard_check_projection(env, tokens, requests)
    env$.tokens_used <- env$.tokens_used + as.numeric(tokens)
    env$.requests_made <- env$.requests_made + as.integer(requests)
    invisible(.rate_guard_usage_snapshot(env))
  }

  env$rollback <- function(tokens = 0, requests = 0L) {
    .validate_nullable_limit(tokens, "tokens", allow_null = FALSE)
    .validate_nullable_limit(requests, "requests", allow_null = FALSE)
    lock <- .rate_guard_lock(env)
    on.exit(.rate_guard_unlock(lock), add = TRUE)
    env$.tokens_used <- max(0, env$.tokens_used - as.numeric(tokens))
    env$.requests_made <- max(0L, env$.requests_made - as.integer(requests))
    invisible(.rate_guard_usage_snapshot(env))
  }

  class(env) <- c("shieldr_rate_guard", class(env))
  env
}

.rate_guard_check_projection <- function(session, tokens, requests) {
  projected_tokens <- session$.tokens_used + as.numeric(tokens)
  projected_requests <- session$.requests_made + as.integer(requests)

  if (!is.null(session$.max_tokens) && projected_tokens > session$.max_tokens) {
    cli::cli_abort(
      "LLM10 rate guard would exceed token limit: projected usage {projected_tokens} is above limit {session$.max_tokens}."
    )
  }
  if (!is.null(session$.max_requests) && projected_requests > session$.max_requests) {
    cli::cli_abort(
      "LLM10 rate guard would exceed request limit: projected count {projected_requests} is above limit {session$.max_requests}."
    )
  }

  invisible(TRUE)
}

.rate_guard_lock <- function(session) {
  if (!isTRUE(session$.concurrent)) {
    return(NULL)
  }
  .check_filelock()
  filelock::lock(session$.lock_path)
}

.rate_guard_unlock <- function(lock) {
  if (!is.null(lock)) {
    filelock::unlock(lock)
  }
  invisible(NULL)
}

.rate_guard_usage_snapshot <- function(session) {
  list(
    tokens_used = session$.tokens_used,
    requests_made = session$.requests_made,
    window_start = session$.window_start,
    max_tokens = session$.max_tokens,
    max_requests = session$.max_requests,
    window_seconds = session$.window_seconds,
    strict = session$.strict,
    concurrent = session$.concurrent
  )
}

.rate_guard_reset_if_expired <- function(session) {
  elapsed <- as.numeric(difftime(Sys.time(), session$.window_start, units = "secs"))
  if (elapsed > session$.window_seconds) {
    session$.tokens_used <- 0
    session$.requests_made <- 0L
    session$.window_start <- Sys.time()
  }
  invisible(session)
}

.validate_nullable_limit <- function(x, arg, allow_null = TRUE) {
  if (is.null(x) && allow_null) {
    return(invisible(TRUE))
  }
  if (!(is.numeric(x) && length(x) == 1L && !is.na(x) && x >= 0)) {
    cli::cli_abort("{.arg {arg}} must be a non-negative number or {.code NULL}.")
  }
  invisible(TRUE)
}

.validate_flag <- function(x, arg) {
  if (!(is.logical(x) && length(x) == 1L && !is.na(x))) {
    cli::cli_abort("{.arg {arg}} must be {.code TRUE} or {.code FALSE}.")
  }
  invisible(TRUE)
}

.check_filelock <- function() {
  rlang::check_installed(
    "filelock",
    reason = "Install filelock for concurrent rate_guard() support."
  )
}
