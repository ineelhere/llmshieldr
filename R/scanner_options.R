#' Configure optional text scanners
#'
#' `scanner_options()` enables optional checks that sit beside deterministic
#' policy rules. These scanners are intentionally lightweight and local. They
#' are useful for catching common wrappers around risky text, such as invisible
#' Unicode format characters, encoded payloads, disallowed URLs, simple token
#' budget violations, language allowlists, and topic bans.
#'
#' @details
#' Scanner findings use the same finding schema as rule findings and therefore
#' contribute to `risk_score`, `action`, audit logs, and explanations.
#'
#' The encoded-payload scanner tries URL decoding and base64 decoding on
#' candidate substrings, then runs the active policy rules over decoded text.
#' It does not execute decoded content. The language scanner is deliberately
#' basic unless `language_fn` is supplied; a custom function should accept a
#' single string and return a language label such as `"en"`, `"es"`, or
#' `"non_latin"`.
#'
#' @param invisible_text Whether to flag Unicode format characters such as
#'   zero-width spaces. Normalization removes these characters before rule
#'   matching, but a finding records that evasive formatting was present.
#' @param encoded_payloads Whether to inspect URL-encoded and base64-like
#'   payloads by decoding candidates and scanning the decoded text.
#' @param urls Whether to create low-severity inventory findings for URLs.
#' @param malicious_urls Whether to flag URLs whose hosts are explicitly
#'   blocked or fall outside `allowed_url_hosts`.
#' @param max_tokens Optional maximum estimated tokens for a single scanned
#'   text. Exceeding the limit creates an OWASP LLM10 block finding.
#' @param allowed_languages Optional language allowlist. Uses `language_fn`
#'   when supplied, otherwise a minimal ASCII/non-Latin heuristic.
#' @param language_fn Optional function that receives text and returns a single
#'   language label.
#' @param blocked_topics Optional character vector of regular expressions, or a
#'   named character vector. Matches create topic-ban findings.
#' @param blocked_url_hosts Optional character vector of blocked URL hosts.
#' @param allowed_url_hosts Optional character vector of allowed URL hosts. When
#'   supplied, URL hosts outside the allowlist are flagged.
#'
#' @return A `shieldr_scanner_options` object.
#' @examples
#' scanners <- scanner_options(
#'   max_tokens = 500,
#'   blocked_topics = c("internal layoffs", "unreleased earnings")
#' )
#'
#' scan_prompt("Summarize this public note.", scanners = scanners)
#' @export
scanner_options <- function(invisible_text = TRUE,
                            encoded_payloads = TRUE,
                            urls = FALSE,
                            malicious_urls = TRUE,
                            max_tokens = NULL,
                            allowed_languages = NULL,
                            language_fn = NULL,
                            blocked_topics = NULL,
                            blocked_url_hosts = NULL,
                            allowed_url_hosts = NULL) {
  .validate_flag(invisible_text, "invisible_text")
  .validate_flag(encoded_payloads, "encoded_payloads")
  .validate_flag(urls, "urls")
  .validate_flag(malicious_urls, "malicious_urls")
  .validate_nullable_limit(max_tokens, "max_tokens")
  if (!is.null(allowed_languages) && !is.character(allowed_languages)) {
    cli::cli_abort("{.arg allowed_languages} must be a character vector or {.code NULL}.")
  }
  if (!is.null(language_fn) && !is.function(language_fn)) {
    cli::cli_abort("{.arg language_fn} must be a function or {.code NULL}.")
  }
  if (!is.null(blocked_topics) && !is.character(blocked_topics)) {
    cli::cli_abort("{.arg blocked_topics} must be a character vector or {.code NULL}.")
  }
  if (!is.null(blocked_url_hosts) && !is.character(blocked_url_hosts)) {
    cli::cli_abort("{.arg blocked_url_hosts} must be a character vector or {.code NULL}.")
  }
  if (!is.null(allowed_url_hosts) && !is.character(allowed_url_hosts)) {
    cli::cli_abort("{.arg allowed_url_hosts} must be a character vector or {.code NULL}.")
  }

  structure(
    list(
      invisible_text = invisible_text,
      encoded_payloads = encoded_payloads,
      urls = urls,
      malicious_urls = malicious_urls,
      max_tokens = max_tokens,
      allowed_languages = allowed_languages,
      language_fn = language_fn,
      blocked_topics = blocked_topics,
      blocked_url_hosts = blocked_url_hosts,
      allowed_url_hosts = allowed_url_hosts
    ),
    class = "shieldr_scanner_options"
  )
}

.validate_scanner_options <- function(scanners) {
  if (is.null(scanners)) {
    return(scanner_options(
      invisible_text = FALSE,
      encoded_payloads = FALSE,
      urls = FALSE,
      malicious_urls = FALSE
    ))
  }
  if (!inherits(scanners, "shieldr_scanner_options")) {
    cli::cli_abort("{.arg scanners} must be created by {.fn scanner_options}.")
  }
  scanners
}

.run_scanners <- function(original_text, normalised_text, policy, scanners, stage = "text") {
  .check_string(original_text, "original_text", allow_empty = TRUE)
  .check_string(normalised_text, "normalised_text", allow_empty = TRUE)
  .check_policy(policy)
  scanners <- .validate_scanner_options(scanners)

  findings <- list()
  if (isTRUE(scanners$invisible_text)) {
    findings <- c(findings, .scan_invisible_text(original_text))
  }
  if (isTRUE(scanners$encoded_payloads)) {
    findings <- c(findings, .scan_encoded_payloads(original_text, policy))
  }
  if (isTRUE(scanners$urls) || isTRUE(scanners$malicious_urls)) {
    findings <- c(findings, .scan_urls(original_text, scanners))
  }
  if (!is.null(scanners$max_tokens)) {
    findings <- c(findings, .scan_token_limit(normalised_text, scanners$max_tokens))
  }
  if (!is.null(scanners$allowed_languages)) {
    findings <- c(findings, .scan_language(normalised_text, scanners))
  }
  if (!is.null(scanners$blocked_topics)) {
    findings <- c(findings, .scan_topics(normalised_text, scanners$blocked_topics))
  }

  lapply(findings, function(finding) {
    finding$stage <- stage
    finding
  })
}

.scan_invisible_text <- function(text) {
  if (!stringi::stri_detect_regex(text, "\\p{Cf}")) {
    return(list())
  }
  list(.scanner_finding(
    rule_id = "llm01.scanner.invisible_text",
    owasp = "llm01",
    severity = "medium",
    action = "redact",
    description = "Text contains invisible Unicode format characters.",
    match = NA_character_
  ))
}

.scan_encoded_payloads <- function(text, policy) {
  decoded <- unique(.decoded_payload_candidates(text))
  decoded <- decoded[nzchar(decoded) & decoded != text]
  if (length(decoded) == 0L) {
    return(list())
  }

  out <- list()
  for (candidate in decoded) {
    decoded_norm <- .normalise_text(candidate)
    candidate_findings <- .run_rules(decoded_norm, policy)
    if (length(candidate_findings) == 0L) {
      next
    }
    for (finding in candidate_findings) {
      finding$rule_id <- paste0(finding$rule_id %||% "llm.scanner.encoded_payload", ".encoded")
      finding$description <- paste(
        "Encoded payload decodes to content that triggered a policy rule.",
        finding$description %||% "",
        sep = " "
      )
      finding$match <- NA_character_
      finding$start <- NA_integer_
      finding$end <- NA_integer_
      finding$source <- "scanner"
      out[[length(out) + 1L]] <- finding
    }
  }
  out
}

.decoded_payload_candidates <- function(text) {
  candidates <- character()

  if (grepl("%[0-9A-Fa-f]{2}", text, perl = TRUE)) {
    decoded <- tryCatch(utils::URLdecode(text), error = function(e) "")
    candidates <- c(candidates, decoded)
  }

  base64_hits <- gregexpr("\\b[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])", text, perl = TRUE)[[1]]
  if (!(length(base64_hits) == 0L || identical(base64_hits[[1]], -1L))) {
    lengths <- attr(base64_hits, "match.length")
    for (i in seq_along(base64_hits)) {
      raw_value <- substr(text, base64_hits[[i]], base64_hits[[i]] + lengths[[i]] - 1L)
      decoded <- tryCatch(
        rawToChar(jsonlite::base64_dec(raw_value)),
        error = function(e) ""
      )
      candidates <- c(candidates, decoded)
    }
  }

  .compact_chr(candidates)
}

.scan_urls <- function(text, scanners) {
  urls <- .find_urls(text)
  if (length(urls) == 0L) {
    return(list())
  }

  out <- list()
  for (url in urls) {
    host <- .url_host(url)
    blocked <- !is.null(scanners$blocked_url_hosts) && host %in% scanners$blocked_url_hosts
    outside_allowlist <- !is.null(scanners$allowed_url_hosts) && !host %in% scanners$allowed_url_hosts

    if (isTRUE(scanners$malicious_urls) && (blocked || outside_allowlist)) {
      out[[length(out) + 1L]] <- .scanner_finding(
        rule_id = "llm05.scanner.url.host",
        owasp = "llm05",
        severity = "high",
        action = "block",
        description = "URL host is blocked or outside the configured allowlist.",
        match = url
      )
    } else if (isTRUE(scanners$urls)) {
      out[[length(out) + 1L]] <- .scanner_finding(
        rule_id = "llm02.scanner.url.present",
        owasp = "llm02",
        severity = "low",
        action = "allow",
        description = "Text contains a URL.",
        match = url
      )
    }
  }
  out
}

.find_urls <- function(text) {
  hits <- gregexpr("https?://[^\\s<>()\"']+", text, perl = TRUE)[[1]]
  if (length(hits) == 0L || identical(hits[[1]], -1L)) {
    return(character())
  }
  lengths <- attr(hits, "match.length")
  vapply(seq_along(hits), function(i) {
    substr(text, hits[[i]], hits[[i]] + lengths[[i]] - 1L)
  }, character(1))
}

.url_host <- function(url) {
  parsed <- tryCatch(utils::URLdecode(url), error = function(e) url)
  host <- sub("^https?://", "", parsed, ignore.case = TRUE)
  host <- sub("[:/].*$", "", host)
  tolower(host)
}

.scan_token_limit <- function(text, max_tokens) {
  tokens <- .count_tokens(text)
  if (tokens <= max_tokens) {
    return(list())
  }
  list(.scanner_finding(
    rule_id = "llm10.scanner.token_limit",
    owasp = "llm10",
    severity = "critical",
    action = "block",
    description = "Text exceeds the configured scanner token limit.",
    match = as.character(tokens)
  ))
}

.scan_language <- function(text, scanners) {
  language <- if (!is.null(scanners$language_fn)) {
    tryCatch(as.character(scanners$language_fn(text))[[1]], error = function(e) NA_character_)
  } else {
    .detect_language_basic(text)
  }
  if (!is.na(language) && language %in% scanners$allowed_languages) {
    return(list())
  }
  list(.scanner_finding(
    rule_id = "llm09.scanner.language",
    owasp = "llm09",
    severity = "medium",
    action = "block",
    description = "Detected language is outside the configured allowlist.",
    match = language %||% NA_character_
  ))
}

.detect_language_basic <- function(text) {
  if (!nzchar(text)) {
    return("unknown")
  }
  non_ascii <- sum(as.integer(charToRaw(text)) > 127L)
  ratio <- non_ascii / max(nchar(text, type = "bytes"), 1L)
  if (ratio > 0.2) "non_latin" else "en"
}

.scan_topics <- function(text, blocked_topics) {
  out <- list()
  topic_names <- names(blocked_topics)
  if (is.null(topic_names)) {
    topic_names <- blocked_topics
  }
  for (i in seq_along(blocked_topics)) {
    pattern <- blocked_topics[[i]]
    if (!grepl(pattern, text, ignore.case = TRUE, perl = TRUE)) {
      next
    }
    topic <- topic_names[[i]]
    out[[length(out) + 1L]] <- .scanner_finding(
      rule_id = "llm09.scanner.topic_ban",
      owasp = "llm09",
      severity = "high",
      action = "block",
      description = paste0("Text matches blocked topic pattern: ", topic),
      match = topic
    )
  }
  out
}

.scanner_finding <- function(rule_id,
                             owasp,
                             severity,
                             action,
                             description,
                             match = NA_character_) {
  list(
    rule_id = rule_id,
    owasp = owasp,
    severity = severity,
    action = action,
    description = description,
    match = match,
    start = NA_integer_,
    end = NA_integer_,
    source = "scanner"
  )
}
