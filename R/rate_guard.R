#' Create or check a rate guard
#'
#' Rate guards are explicit stateful environments used to cap token, request,
#' and cost budgets for LLM workflows. Resource exhaustion is covered by OWASP
#' LLM10; see <https://genai.owasp.org/llm-top-10/>.
#'
#' @details
#' Calling `rate_guard()` with limits and `session = NULL` creates a new
#' `shieldr_rate_guard` environment. The environment stores counters for the
#' current window and exposes two methods:
#'
#' - `$usage()`: returns current counters and configured limits
#' - `$update(tokens, cost_usd)`: increments tokens, request count, and cost
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
#' @param cost_limit_usd Maximum cost per window, or `NULL`.
#' @param window_seconds Window length in seconds.
#'
#' @return When creating a guard, a `shieldr_rate_guard` environment. When
#'   checking a guard, `TRUE` if usage is within limits.
#' @examples
#' guard <- rate_guard(max_tokens = 100)
#' guard$update(tokens = 10, cost_usd = 0)
#' rate_guard(guard)
#' @export
rate_guard <- function(session = NULL,
                       max_tokens = NULL,
                       max_requests = NULL,
                       cost_limit_usd = NULL,
                       window_seconds = 3600L) {
  if (is.null(session)) {
    .validate_nullable_limit(max_tokens, "max_tokens")
    .validate_nullable_limit(max_requests, "max_requests")
    .validate_nullable_limit(cost_limit_usd, "cost_limit_usd")
    .validate_nullable_limit(window_seconds, "window_seconds", allow_null = FALSE)

    env <- new.env(parent = emptyenv())
    env$.tokens_used <- 0
    env$.requests_made <- 0L
    env$.cost_usd <- 0
    env$.window_start <- Sys.time()
    env$.max_tokens <- max_tokens
    env$.max_requests <- max_requests
    env$.cost_limit_usd <- cost_limit_usd
    env$.window_seconds <- as.integer(window_seconds)

    env$usage <- function() {
      .rate_guard_reset_if_expired(env)
      list(
        tokens_used = env$.tokens_used,
        requests_made = env$.requests_made,
        cost_usd = env$.cost_usd,
        window_start = env$.window_start,
        max_tokens = env$.max_tokens,
        max_requests = env$.max_requests,
        cost_limit_usd = env$.cost_limit_usd,
        window_seconds = env$.window_seconds
      )
    }

    env$update <- function(tokens, cost_usd = 0) {
      .validate_nullable_limit(tokens, "tokens", allow_null = FALSE)
      .validate_nullable_limit(cost_usd, "cost_usd", allow_null = FALSE)
      .rate_guard_reset_if_expired(env)
      env$.tokens_used <- env$.tokens_used + as.numeric(tokens)
      env$.requests_made <- env$.requests_made + 1L
      env$.cost_usd <- env$.cost_usd + as.numeric(cost_usd)
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
  if (!is.null(usage$cost_limit_usd) && usage$cost_usd > usage$cost_limit_usd) {
    cli::cli_abort("LLM10 rate guard exceeded: cost ${usage$cost_usd} is above limit ${usage$cost_limit_usd}.")
  }

  TRUE
}

.rate_guard_reset_if_expired <- function(session) {
  elapsed <- as.numeric(difftime(Sys.time(), session$.window_start, units = "secs"))
  if (elapsed > session$.window_seconds) {
    session$.tokens_used <- 0
    session$.requests_made <- 0L
    session$.cost_usd <- 0
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
