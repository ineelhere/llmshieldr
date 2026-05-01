#' Create or check a rate guard
#'
#' Rate guards are explicit stateful environments used to cap token and request
#' budgets for LLM workflows. Resource exhaustion is covered by OWASP
#' LLM10; see <https://genai.owasp.org/llm-top-10/>.
#'
#' @details
#' Calling `rate_guard()` with limits and `session = NULL` creates a new
#' `shieldr_rate_guard` environment. The environment stores counters for the
#' current window and exposes two methods:
#'
#' - `$usage()`: returns current counters and configured limits
#' - `$update(tokens)`: increments tokens and request count
#'
#' Calling `rate_guard(session)` checks the existing environment and returns
#' `TRUE` if all counters are within limits. If a limit has been exceeded, it
#' raises an OWASP LLM10 error with [cli::cli_abort()]. Limits set to `NULL`
#' are disabled for that dimension.
#'
#' Windows reset automatically when `window_seconds` has elapsed. This object
#' is intentionally stateful; it is the one place where llmshieldr expects
#' mutable state, because rate limiting is inherently session-based.
#'
#' @param session A `shieldr_rate_guard` returned by `rate_guard()`, or `NULL`
#'   to create a new guard.
#' @param max_tokens Maximum tokens per window, or `NULL`.
#' @param max_requests Maximum requests per window, or `NULL`.
#' @param window_seconds Window length in seconds.
#'
#' @return When creating a guard, a `shieldr_rate_guard` environment. When
#'   checking a guard, `TRUE` if usage is within limits.
#' @examples
#' guard <- rate_guard(max_tokens = 100)
#' guard$update(tokens = 10)
#' rate_guard(guard)
#' @export
rate_guard <- function(session = NULL,
                       max_tokens = NULL,
                       max_requests = NULL,
                       window_seconds = 3600L) {
  if (is.null(session)) {
    .validate_nullable_limit(max_tokens, "max_tokens")
    .validate_nullable_limit(max_requests, "max_requests")
    .validate_nullable_limit(window_seconds, "window_seconds", allow_null = FALSE)

    env <- new.env(parent = emptyenv())
    env$.tokens_used <- 0
    env$.requests_made <- 0L
    env$.window_start <- Sys.time()
    env$.max_tokens <- max_tokens
    env$.max_requests <- max_requests
    env$.window_seconds <- as.integer(window_seconds)

    env$usage <- function() {
      .rate_guard_reset_if_expired(env)
      list(
        tokens_used = env$.tokens_used,
        requests_made = env$.requests_made,
        window_start = env$.window_start,
        max_tokens = env$.max_tokens,
        max_requests = env$.max_requests,
        window_seconds = env$.window_seconds
      )
    }

    env$update <- function(tokens) {
      .validate_nullable_limit(tokens, "tokens", allow_null = FALSE)
      .rate_guard_reset_if_expired(env)
      env$.tokens_used <- env$.tokens_used + as.numeric(tokens)
      env$.requests_made <- env$.requests_made + 1L
      invisible(env$usage())
    }

    class(env) <- c("shieldr_rate_guard", class(env))
    return(env)
  }

  if (!inherits(session, "shieldr_rate_guard")) {
    cli::cli_abort("{.arg session} must be a {.cls shieldr_rate_guard}.")
  }
  .rate_guard_reset_if_expired(session)
  usage <- session$usage()

  if (!is.null(usage$max_tokens) && usage$tokens_used > usage$max_tokens) {
    cli::cli_abort("LLM10 rate guard exceeded: token usage {usage$tokens_used} is above limit {usage$max_tokens}.")
  }
  if (!is.null(usage$max_requests) && usage$requests_made > usage$max_requests) {
    cli::cli_abort("LLM10 rate guard exceeded: request count {usage$requests_made} is above limit {usage$max_requests}.")
  }

  TRUE
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
