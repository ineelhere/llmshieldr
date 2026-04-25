# ── Sophisticated Error Infrastructure ──────────────────────────────────────
# Centralised error constructors for llmshieldr. Every user-facing error is
# branded, structured, and carries machine-readable metadata.

# ── OWASP label lookup ──────────────────────────────────────────────────────
.owasp_labels <- list(
  LLM01 = "Prompt Injection",
  LLM02 = "Sensitive Information Disclosure",
  LLM06 = "Excessive Agency",
  LLM07 = "System Prompt Leakage",
  LLM09 = "Misinformation"
)

#' Resolve OWASP tag to human-readable label
#' @noRd
#' @keywords internal
.owasp_label <- function(tag) {
  .owasp_labels[[tag]] %||% tag
}

#' Build a severity bar visualisation
#' @noRd
#' @keywords internal
.severity_bar <- function(score, width = 20L) {
  clamped <- min(max(score, 0), 100)
  filled  <- round(clamped / 100 * width)
  empty   <- width - filled
  bar <- paste0(
    strrep("\u2588", filled),
    strrep("\u2591", empty)
  )
  paste0(bar, " ", score, "/100")
}

#' Build a risk badge string
#' @noRd
#' @keywords internal
.risk_badge <- function(band) {
  badges <- list(
    critical = "\u26d4 CRITICAL",
    high     = "\U0001f6a8 HIGH",
    moderate = "\u26a0\ufe0f  MODERATE",
    low      = "\u2705 LOW"
  )
  badges[[band]] %||% toupper(band)
}

# ── Core error: policy block ───────────────────────────────────────────────

#' Abort with a rich policy-block error
#'
#' Used when `secure_chat()` blocks a prompt due to policy violations.
#' Produces a highly structured, branded error condition.
#'
#' @param policy_name Character. The policy that triggered the block.
#' @param findings List. The matched rule objects.
#' @param score Numeric. The aggregate risk score.
#' @param band Character. The severity band.
#' @param call The calling environment (for backtrace attribution).
#'
#' @noRd
#' @keywords internal
abort_policy_block <- function(policy_name, findings, score, band,
                               block_threshold = NULL,
                               call = rlang::caller_env()) {

  # Group finding IDs by OWASP category
  owasp_groups <- list()
  for (f in findings) {
    label <- paste0(f$owasp, " \u2014 ", .owasp_label(f$owasp))
    owasp_groups[[label]] <- c(owasp_groups[[label]], f$id)
  }

  # Build bullet points
  header <- paste0(
    "\u2590\u2588 SHIELD POLICY VIOLATION \u2588\u258c ",
    "Prompt blocked by policy {.val {policy_name}}."
  )

  bullets <- character()

  # Risk score with visual bar
  bullets <- c(bullets, stats::setNames(
    paste0("Risk assessment: ", .risk_badge(band),
           " \u2014 ", .severity_bar(score)),
    "x"
  ))

  # Triggered rules grouped by OWASP category
  for (grp_label in names(owasp_groups)) {
    rule_ids <- owasp_groups[[grp_label]]
    bullets <- c(bullets, stats::setNames(
      paste0("{.strong ", grp_label, "}: ",
             paste0("{.val ", rule_ids, "}", collapse = ", ")),
      "!"
    ))
  }

  # Finding details
  for (f in findings) {
    bullets <- c(bullets, stats::setNames(
      paste0("{.field ", f$id, "}: ", f$description,
             " (severity: ", f$severity, ")"),
      " "
    ))
  }

  # Remediation
  bullets <- c(bullets, stats::setNames(
    "Review and sanitise the prompt before resubmission.",
    "i"
  ))
  bullets <- c(bullets, stats::setNames(
    "Use {.fn preflight_check} to inspect findings in detail.",
    "i"
  ))
  bullets <- c(bullets, stats::setNames(
    paste0(
      "Policy block threshold: ",
      if (is.null(block_threshold)) {
        "see the active policy configuration."
      } else {
        "score >= {.val {block_threshold}}."
      }
    ),
    "i"
  ))

  cli::cli_abort(
    message = c(header, bullets),
    class   = c("llmshieldr_policy_block", "llmshieldr_error"),
    call    = call,
    .envir  = call,
    policy  = policy_name,
    score   = score,
    band    = band,
    rules   = vapply(findings, `[[`, character(1), "id"),
    owasp   = unique(vapply(findings, `[[`, character(1), "owasp"))
  )
}

# ── Core error: validation ─────────────────────────────────────────────────

#' Abort with a structured input-validation error
#'
#' @param arg Character. The argument name that failed validation.
#' @param expected Character. What was expected.
#' @param got Optional character. What was received.
#' @param fn Character. The function name for attribution.
#' @param call The calling environment.
#'
#' @noRd
#' @keywords internal
abort_input_validation <- function(arg, expected, got = NULL,
                                   fn = NULL,
                                   call = rlang::caller_env()) {
  fn_label <- if (!is.null(fn)) paste0(" in {.fn ", fn, "}") else ""
  header <- paste0(
    "\u2590\u2588 SHIELD INPUT ERROR \u2588\u258c ",
    "{.arg ", arg, "} is invalid", fn_label, "."
  )

  bullets <- c(
    "x" = paste0("Expected: ", expected, "."),
    "i" = "Check the function documentation with {.code ?llmshieldr} for details."
  )

  if (!is.null(got)) {
    bullets <- c(
      bullets[1],
      stats::setNames(paste0("Received: ", got, "."), "x"),
      bullets[-1]
    )
  }

  cli::cli_abort(
    message = c(header, bullets),
    class   = c("llmshieldr_input_error", "llmshieldr_error"),
    call    = call,
    .envir  = call,
    arg     = arg
  )
}

# ── Core error: dependency ─────────────────────────────────────────────────

#' Abort with a missing-dependency error
#'
#' @param pkg Character. The missing package name.
#' @param fn Character. The function that requires it.
#' @param call The calling environment.
#'
#' @noRd
#' @keywords internal
abort_missing_dependency <- function(pkg, fn, call = rlang::caller_env()) {
  header <- paste0(
    "\u2590\u2588 SHIELD DEPENDENCY ERROR \u2588\u258c ",
    "The {.pkg ", pkg, "} package is required for {.fn ", fn, "}."
  )

  cli::cli_abort(
    message = c(
      header,
      "x" = "Package {.pkg {pkg}} is not installed or cannot be loaded.",
      "i" = "Install with: {.code install.packages('{pkg}')}.",
      "i" = "See {.url https://github.com/ineelhere/llmshieldr#readme} for setup guidance."
    ),
    class = c("llmshieldr_dependency_error", "llmshieldr_error"),
    call   = call,
    .envir = call,
    pkg    = pkg
  )
}

# ── Core error: provider failure ───────────────────────────────────────────

#' Abort with a provider-call error
#'
#' @param provider_msg Character. The original error message from the provider.
#' @param call The calling environment.
#'
#' @noRd
#' @keywords internal
abort_provider_failure <- function(provider_msg, call = rlang::caller_env()) {
  header <- paste0(
    "\u2590\u2588 SHIELD PROVIDER ERROR \u2588\u258c ",
    "LLM provider call failed during shielded interaction."
  )

  cli::cli_abort(
    message = c(
      header,
      "x" = "{provider_msg}",
      "i" = "Verify the provider configuration and model availability.",
      "i" = "Check network connectivity if using a remote provider.",
      "i" = "The prompt passed all preflight checks before this failure."
    ),
    class = c("llmshieldr_provider_error", "llmshieldr_error"),
    call   = call,
    .envir = call
  )
}

# ── Core error: rule management ────────────────────────────────────────────

#' Abort with a rule-management error
#'
#' @param message Character. The primary error message.
#' @param ... Additional named bullets.
#' @param call The calling environment.
#'
#' @noRd
#' @keywords internal
abort_rule_error <- function(message, ..., call = rlang::caller_env()) {
  header <- paste0(
    "\u2590\u2588 SHIELD RULE ERROR \u2588\u258c ", message
  )

  cli::cli_abort(
    message = c(header, ...),
    class   = c("llmshieldr_rule_error", "llmshieldr_error"),
    call    = call,
    .envir  = call
  )
}

# ── Core error: policy config ─────────────────────────────────────────────

#' Abort with a policy-configuration error
#'
#' @param message Character. The primary error message.
#' @param ... Additional named bullets.
#' @param call The calling environment.
#'
#' @noRd
#' @keywords internal
abort_policy_error <- function(message, ..., call = rlang::caller_env()) {
  header <- paste0(
    "\u2590\u2588 SHIELD POLICY ERROR \u2588\u258c ", message
  )

  cli::cli_abort(
    message = c(header, ...),
    class   = c("llmshieldr_policy_error", "llmshieldr_error"),
    call    = call,
    .envir  = call
  )
}

# ── Core error: resource not found ─────────────────────────────────────────

#' Abort with a resource-not-found error
#'
#' @param message Character. The primary error message.
#' @param ... Additional named bullets.
#' @param call The calling environment.
#'
#' @noRd
#' @keywords internal
abort_not_found <- function(message, ..., call = rlang::caller_env()) {
  header <- paste0(
    "\u2590\u2588 SHIELD NOT FOUND \u2588\u258c ", message
  )

  cli::cli_abort(
    message = c(header, ...),
    class   = c("llmshieldr_not_found_error", "llmshieldr_error"),
    call    = call,
    .envir  = call
  )
}
