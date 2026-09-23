#' Configure versioned secret detection
#'
#' Creates an opt-in signature registry for common provider credentials plus a
#' contextual high-entropy token check. Values matching an allowlist pattern or
#' obvious placeholders are ignored. Detection never verifies a credential
#' over the network.
#'
#' @param signatures Optional named character vector of regular expressions.
#'   `NULL` uses the package registry.
#' @param allowlist Character vector of regular expressions to ignore.
#' @param min_entropy Minimum Shannon entropy for contextual generic tokens.
#' @param decoding_depth Maximum bounded URL/base64 decode passes, from 0 to 3.
#' @param version Registry version recorded with findings.
#' @param show_stats Show construction time and available usage metrics.
#'
#' @return A `shieldr_secret_registry` object for [scanner_options()].
#' @examples
#' scanners <- scanner_options(secrets = secret_registry())
#' @export
secret_registry <- function(signatures = NULL,
                            allowlist = c("(?i)(example|sample|placeholder|dummy|redacted|your[_ -]?(key|token))"),
                            min_entropy = 3.5,
                            decoding_depth = 1L,
                            version = "2026.1",
                            show_stats = FALSE) {
  stats <- .stats_begin(show_stats, "secret_registry")
  on.exit(.stats_end(stats), add = TRUE)
  signatures <- signatures %||% .default_secret_signatures()
  if (!is.character(signatures) || is.null(names(signatures)) ||
      any(!nzchar(names(signatures))) || anyNA(signatures)) {
    cli::cli_abort("{.arg signatures} must be a named character vector without missing values.")
  }
  if (!is.character(allowlist) || anyNA(allowlist)) {
    cli::cli_abort("{.arg allowlist} must be a character vector without missing values.")
  }
  .check_number_between(min_entropy, "min_entropy", 0, 8)
  .validate_count(decoding_depth, "decoding_depth")
  if (decoding_depth > 3L) cli::cli_abort("{.arg decoding_depth} must be no greater than 3.")
  .check_string(version, "version")
  structure(
    list(
      signatures = signatures,
      allowlist = allowlist,
      min_entropy = min_entropy,
      decoding_depth = as.integer(decoding_depth),
      version = version
    ),
    class = "shieldr_secret_registry"
  )
}

.default_secret_signatures <- function() {
  c(
    google_api_key = "\\bAIza[0-9A-Za-z_-]{35}\\b",
    github_token = "\\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36,255}\\b",
    openai_key = "\\bsk-(?:proj-)?[0-9A-Za-z_-]{20,}\\b",
    slack_token = "\\bxox[baprs]-[0-9A-Za-z-]{10,}\\b",
    stripe_key = "\\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\\b",
    private_key = "-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
  )
}

.validate_secret_registry <- function(x) {
  if (is.null(x)) return(invisible(TRUE))
  if (!inherits(x, "shieldr_secret_registry")) {
    cli::cli_abort("{.arg secrets} must be created by {.fn secret_registry} or be {.code NULL}.")
  }
  invisible(TRUE)
}

.scan_secret_registry <- function(text, registry) {
  if (is.null(registry)) return(list())
  candidates <- list(list(text = text, encoding = "plain"))
  current <- text
  if (registry$decoding_depth > 0L) {
    for (depth in seq_len(registry$decoding_depth)) {
      decoded <- .decoded_payload_candidates(current)
      decoded <- decoded[nzchar(decoded) & decoded != current]
      if (length(decoded) == 0L) break
      for (value in decoded) {
        candidates[[length(candidates) + 1L]] <- list(text = value, encoding = paste0("decoded_", depth))
      }
      current <- decoded[[1L]]
    }
  }

  out <- list()
  for (candidate in candidates) {
    for (id in names(registry$signatures)) {
      hits <- .pattern_matches(candidate$text, registry$signatures[[id]])
      for (hit in hits) {
        if (.secret_allowlisted(hit$value, registry$allowlist)) next
        finding <- .scanner_finding(
          paste0("llm02.secret.", id), "llm02", "critical", "redact",
          paste0("Detected credential format: ", id, "."),
          if (identical(candidate$encoding, "plain")) hit$value else NA_character_
        )
        if (identical(candidate$encoding, "plain")) {
          finding$start <- hit$start
          finding$end <- hit$end
        }
        finding$registry_version <- registry$version
        finding$encoding <- candidate$encoding
        out[[length(out) + 1L]] <- finding
      }
    }
  }

  generic <- .contextual_secret_candidates(text)
  for (hit in generic) {
    entropy <- .shannon_entropy(hit$value)
    if (entropy < registry$min_entropy || .secret_allowlisted(hit$value, registry$allowlist)) next
    finding <- .scanner_finding(
      "llm02.secret.high_entropy", "llm02", "high", "redact",
      "Detected a high-entropy token in credential context.", hit$value
    )
    finding$start <- hit$start
    finding$end <- hit$end
    finding$entropy <- entropy
    finding$registry_version <- registry$version
    finding$encoding <- "plain"
    out[[length(out) + 1L]] <- finding
  }
  .dedupe_findings(out)
}

.pattern_matches <- function(text, pattern) {
  hits <- gregexpr(pattern, text, perl = TRUE)[[1L]]
  if (length(hits) == 0L || identical(hits[[1L]], -1L)) return(list())
  lengths <- attr(hits, "match.length")
  lapply(seq_along(hits), function(i) {
    start <- as.integer(hits[[i]])
    end <- start + as.integer(lengths[[i]]) - 1L
    list(start = start, end = end, value = substr(text, start, end))
  })
}

.contextual_secret_candidates <- function(text) {
  pattern <- "(?i)(?:api[_ -]?key|access[_ -]?token|secret|password|credential)\\s*[:=]\\s*['\"]?([A-Za-z0-9_./+=-]{16,})"
  hits <- gregexpr(pattern, text, perl = TRUE)[[1L]]
  if (length(hits) == 0L || identical(hits[[1L]], -1L)) return(list())
  lengths <- attr(hits, "match.length")
  out <- list()
  for (i in seq_along(hits)) {
    full_start <- as.integer(hits[[i]])
    full <- substr(text, full_start, full_start + as.integer(lengths[[i]]) - 1L)
    token_hit <- regexpr("[A-Za-z0-9_./+=-]{16,}['\"]?$", full, perl = TRUE)
    if (identical(as.integer(token_hit[[1L]]), -1L)) next
    value <- regmatches(full, token_hit)
    value <- sub("['\"]$", "", value)
    start <- full_start + as.integer(token_hit[[1L]]) - 1L
    out[[length(out) + 1L]] <- list(start = start, end = start + nchar(value) - 1L, value = value)
  }
  out
}

.secret_allowlisted <- function(value, allowlist) {
  any(vapply(allowlist, function(pattern) grepl(pattern, value, perl = TRUE), logical(1)))
}

.shannon_entropy <- function(value) {
  chars <- strsplit(value, "", fixed = TRUE)[[1L]]
  p <- table(chars) / length(chars)
  -sum(p * log2(p))
}
