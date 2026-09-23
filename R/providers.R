#' Create an optional guardrail provider
#'
#' Defines a narrow adapter contract for external or local detectors. The
#' provider function receives `text`, `stage`, and a metadata list, and returns
#' either a list of findings or `list(findings = ..., status = ...)`. Nothing is
#' contacted until a scan using the provider runs.
#'
#' @param id Stable provider identifier.
#' @param scan Function with arguments `text`, `stage`, and `metadata`.
#' @param version Detector, ruleset, or service version.
#' @param stages Stages on which the provider may run.
#' @param on_error Whether provider errors create a blocking finding or are
#'   skipped with a warning.
#' @param retries Number of retries after the first failed call.
#' @param timeout_seconds Optional elapsed-time limit for each attempt. R and
#'   the underlying client must support interruption for this to stop promptly.
#' @param show_stats Show construction time and available usage metrics.
#'
#' @return A `shieldr_provider` object for [scanner_options()].
#' @examples
#' detector <- guardrail_provider(
#'   "example/local",
#'   function(text, stage, metadata) list()
#' )
#' scan_prompt("hello", scanners = scanner_options(providers = list(detector)))
#' @export
guardrail_provider <- function(id,
                               scan,
                               version = "unversioned",
                               stages = c("prompt", "context", "output", "tool_call", "tool_output", "document"),
                               on_error = c("block", "skip"),
                               retries = 0L,
                               timeout_seconds = NULL,
                               show_stats = FALSE) {
  stats <- .stats_begin(show_stats, "guardrail_provider")
  on.exit(.stats_end(stats), add = TRUE)
  .check_string(id, "id")
  if (!is.function(scan)) cli::cli_abort("{.arg scan} must be a function.")
  .check_string(version, "version")
  if (!is.character(stages) || length(stages) == 0L || anyNA(stages)) {
    cli::cli_abort("{.arg stages} must be a non-empty character vector without missing values.")
  }
  allowed_stages <- c("prompt", "context", "output", "tool_call", "tool_output", "document")
  unknown <- setdiff(stages, allowed_stages)
  if (length(unknown) > 0L) {
    cli::cli_abort("Unknown provider stage{?s}: {.val {unknown}}.")
  }
  on_error <- match.arg(on_error)
  .validate_count(retries, "retries")
  .validate_optional_positive(timeout_seconds, "timeout_seconds")
  structure(
    list(
      id = id,
      scan = scan,
      version = version,
      stages = unique(stages),
      on_error = on_error,
      retries = as.integer(retries),
      timeout_seconds = timeout_seconds
    ),
    class = "shieldr_provider"
  )
}

#' Create a custom entity recognizer
#'
#' A recognizer function receives one text string and returns a data frame or a
#' list of records with `start` and `end` character offsets. Optional fields are
#' `confidence`, `entity_type`, and `normalised`.
#'
#' @param id Stable recognizer identifier.
#' @param recognize Function accepting a single text string.
#' @param entity_type Entity label used when a returned record omits one.
#' @param version Recognizer or ruleset version.
#' @param locales Optional locale labels describing evaluated coverage.
#' @param severity Finding severity.
#' @param action Finding action.
#' @param show_stats Show construction time and available usage metrics.
#'
#' @return A `shieldr_recognizer` object for [scanner_options()].
#' @examples
#' recognizer <- entity_recognizer(
#'   "example/member-id",
#'   function(text) data.frame(start = 1L, end = 6L),
#'   entity_type = "MEMBER_ID"
#' )
#' @export
entity_recognizer <- function(id,
                              recognize,
                              entity_type,
                              version = "unversioned",
                              locales = NULL,
                              severity = "high",
                              action = "redact",
                              show_stats = FALSE) {
  stats <- .stats_begin(show_stats, "entity_recognizer")
  on.exit(.stats_end(stats), add = TRUE)
  .check_string(id, "id")
  if (!is.function(recognize)) cli::cli_abort("{.arg recognize} must be a function.")
  .check_string(entity_type, "entity_type")
  .check_string(version, "version")
  if (!is.null(locales) && (!is.character(locales) || anyNA(locales))) {
    cli::cli_abort("{.arg locales} must be a character vector without missing values or {.code NULL}.")
  }
  .check_choice(severity, "severity", .shieldr_severities())
  .check_choice(action, "action", .shieldr_rule_actions())
  structure(
    list(
      id = id,
      recognize = recognize,
      entity_type = entity_type,
      version = version,
      locales = locales,
      severity = severity,
      action = action
    ),
    class = "shieldr_recognizer"
  )
}

#' Native checksum-aware recognizers
#'
#' Returns opt-in local recognizers for payment-card numbers (Luhn), IBANs
#' (mod-97), and IPv4 addresses. These are deterministic signals and should be
#' evaluated on application-specific benign and sensitive text.
#'
#' @param include Any of `"credit_card"`, `"iban"`, and `"ipv4"`.
#' @param show_stats Show construction time and available usage metrics.
#'
#' @return A list of `shieldr_recognizer` objects.
#' @examples
#' scanners <- scanner_options(recognizers = native_recognizers())
#' @export
native_recognizers <- function(include = c("credit_card", "iban", "ipv4"),
                               show_stats = FALSE) {
  stats <- .stats_begin(show_stats, "native_recognizers")
  on.exit(.stats_end(stats), add = TRUE)
  choices <- c("credit_card", "iban", "ipv4")
  if (!is.character(include) || anyNA(include) || any(!include %in% choices)) {
    cli::cli_abort("{.arg include} must contain only {.val {choices}}.")
  }
  makers <- list(
    credit_card = function() entity_recognizer(
      "native/credit-card-luhn", .recognize_credit_cards, "CREDIT_CARD",
      version = "1", locales = "global"
    ),
    iban = function() entity_recognizer(
      "native/iban-mod97", .recognize_ibans, "IBAN",
      version = "1", locales = "IBAN countries"
    ),
    ipv4 = function() entity_recognizer(
      "native/ipv4", .recognize_ipv4, "IP_ADDRESS",
      version = "1", locales = "global", severity = "medium"
    )
  )
  unname(lapply(unique(include), function(name) makers[[name]]()))
}

.validate_provider_list <- function(x) {
  if (!is.list(x) || any(!vapply(x, inherits, logical(1), "shieldr_provider"))) {
    cli::cli_abort("{.arg providers} must be a list of objects from {.fn guardrail_provider}.")
  }
  invisible(TRUE)
}

.validate_recognizer_list <- function(x) {
  if (!is.list(x) || any(!vapply(x, inherits, logical(1), "shieldr_recognizer"))) {
    cli::cli_abort("{.arg recognizers} must be a list of objects from {.fn entity_recognizer}.")
  }
  invisible(TRUE)
}

.run_guardrail_providers <- function(providers, text, stage, metadata = list()) {
  if (length(providers) == 0L) return(list())
  out <- list()
  for (provider in providers) {
    if (!stage %in% provider$stages) next
    result <- .retry_call(
      function() provider$scan(text = text, stage = stage, metadata = metadata),
      retries = provider$retries,
      timeout_seconds = provider$timeout_seconds
    )
    if (inherits(result, "error")) {
      if (identical(provider$on_error, "block")) {
        finding <- .synthetic_finding(
          "llm01.provider.failure", "llm01", "critical",
          paste0("Required guardrail provider failed: ", provider$id, "."),
          action = "block"
        )
        finding$provider_id <- provider$id
        finding$provider_version <- provider$version
        finding$status <- "failed"
        out[[length(out) + 1L]] <- finding
      } else {
        cli::cli_warn("Guardrail provider {.val {provider$id}} failed and was skipped.")
      }
      next
    }
    findings <- if (is.list(result) && !is.null(result$findings)) result$findings else result
    findings <- .coerce_provider_findings(findings, provider, stage)
    out <- c(out, findings)
  }
  out
}

.coerce_provider_findings <- function(findings, provider, stage) {
  if (is.null(findings) || length(findings) == 0L) return(list())
  if (is.data.frame(findings)) {
    findings <- lapply(seq_len(nrow(findings)), function(i) as.list(findings[i, , drop = FALSE]))
  }
  if (is.list(findings) && !is.null(findings$rule_id)) findings <- list(findings)
  if (!is.list(findings) || any(!vapply(findings, is.list, logical(1)))) {
    cli::cli_abort("Guardrail provider {.val {provider$id}} returned invalid findings.")
  }
  lapply(findings, function(finding) {
    finding$rule_id <- as.character(finding$rule_id %||% paste0("llm01.provider.", provider$id))[[1L]]
    finding$owasp <- tolower(as.character(finding$owasp %||% "llm01")[[1L]])
    finding$severity <- tolower(as.character(finding$severity %||% "medium")[[1L]])
    finding$action <- tolower(as.character(finding$action %||% "redact")[[1L]])
    finding$description <- as.character(finding$description %||% "External guardrail provider finding.")[[1L]]
    finding$match <- as.character(finding$match %||% NA_character_)[[1L]]
    finding$start <- suppressWarnings(as.integer(finding$start %||% NA_integer_)[[1L]])
    finding$end <- suppressWarnings(as.integer(finding$end %||% NA_integer_)[[1L]])
    finding$source <- "provider"
    finding$stage <- stage
    finding$provider_id <- provider$id
    finding$provider_version <- provider$version
    .check_choice(finding$severity, "provider finding severity", .shieldr_severities())
    .check_choice(finding$action, "provider finding action", .shieldr_rule_actions())
    finding
  })
}

.run_recognizers <- function(recognizers, text, stage) {
  out <- list()
  for (recognizer in recognizers) {
    spans <- tryCatch(recognizer$recognize(text), error = identity)
    if (inherits(spans, "error")) {
      cli::cli_warn("Entity recognizer {.val {recognizer$id}} failed and was skipped.")
      next
    }
    if (is.null(spans) || length(spans) == 0L) next
    if (is.data.frame(spans)) {
      spans <- lapply(seq_len(nrow(spans)), function(i) as.list(spans[i, , drop = FALSE]))
    }
    if (is.list(spans) && !is.null(spans$start)) spans <- list(spans)
    if (!is.list(spans) || any(!vapply(spans, is.list, logical(1)))) {
      cli::cli_abort("Entity recognizer {.val {recognizer$id}} returned invalid spans.")
    }
    for (span in spans) {
      start <- suppressWarnings(as.integer(span$start %||% NA_integer_)[[1L]])
      end <- suppressWarnings(as.integer(span$end %||% NA_integer_)[[1L]])
      if (is.na(start) || is.na(end) || start < 1L || end < start || end > nchar(text)) {
        cli::cli_abort("Entity recognizer {.val {recognizer$id}} returned an invalid span.")
      }
      finding <- .scanner_finding(
        rule_id = paste0("llm02.recognizer.", gsub("[^A-Za-z0-9_.-]", ".", recognizer$id)),
        owasp = "llm02",
        severity = recognizer$severity,
        action = recognizer$action,
        description = paste0("Detected ", span$entity_type %||% recognizer$entity_type, "."),
        match = substr(text, start, end)
      )
      finding$start <- start
      finding$end <- end
      finding$source <- "recognizer"
      finding$stage <- stage
      finding$entity_type <- span$entity_type %||% recognizer$entity_type
      finding$confidence <- suppressWarnings(as.numeric(span$confidence %||% NA_real_)[[1L]])
      finding$normalised <- span$normalised %||% NA_character_
      finding$recognizer_id <- recognizer$id
      finding$recognizer_version <- recognizer$version
      out[[length(out) + 1L]] <- finding
    }
  }
  out
}

.recognize_credit_cards <- function(text) {
  .regex_spans(text, "(?<![0-9])(?:[0-9][ -]?){12,18}[0-9](?![0-9])", function(value) {
    digits <- gsub("[^0-9]", "", value)
    length_ok <- nchar(digits) >= 13L && nchar(digits) <= 19L
    length_ok && length(unique(strsplit(digits, "", fixed = TRUE)[[1L]])) > 1L && .luhn_valid(digits)
  }, "CREDIT_CARD")
}

.recognize_ibans <- function(text) {
  spans <- .regex_spans(
    toupper(text),
    "(?<![A-Z0-9])[A-Z]{2}[0-9]{2}(?:[ ]?[A-Z0-9]){11,30}(?![A-Z0-9])",
    function(value) .iban_valid(gsub("[ ]", "", value)),
    "IBAN"
  )
  spans
}

.recognize_ipv4 <- function(text) {
  .regex_spans(text, "(?<![0-9])(?:[0-9]{1,3}\\.){3}[0-9]{1,3}(?![0-9])", function(value) {
    parts <- suppressWarnings(as.integer(strsplit(value, ".", fixed = TRUE)[[1L]]))
    length(parts) == 4L && all(!is.na(parts) & parts >= 0L & parts <= 255L)
  }, "IP_ADDRESS")
}

.regex_spans <- function(text, pattern, validate, entity_type) {
  hit <- gregexpr(pattern, text, perl = TRUE)[[1L]]
  if (length(hit) == 0L || identical(hit[[1L]], -1L)) return(list())
  lengths <- attr(hit, "match.length")
  out <- list()
  for (i in seq_along(hit)) {
    start <- as.integer(hit[[i]])
    end <- start + as.integer(lengths[[i]]) - 1L
    value <- substr(text, start, end)
    if (!isTRUE(validate(value))) next
    out[[length(out) + 1L]] <- list(
      start = start, end = end, entity_type = entity_type,
      confidence = 1, normalised = gsub("[ -]", "", value)
    )
  }
  out
}

.luhn_valid <- function(digits) {
  values <- rev(as.integer(strsplit(digits, "", fixed = TRUE)[[1L]]))
  even <- seq_along(values) %% 2L == 0L
  values[even] <- values[even] * 2L
  values[values > 9L] <- values[values > 9L] - 9L
  sum(values) %% 10L == 0L
}

.iban_valid <- function(value) {
  if (!grepl("^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$", value)) return(FALSE)
  rotated <- paste0(substr(value, 5L, nchar(value)), substr(value, 1L, 4L))
  chars <- strsplit(rotated, "", fixed = TRUE)[[1L]]
  numeric_text <- paste0(ifelse(grepl("[A-Z]", chars), match(chars, LETTERS) + 9L, chars), collapse = "")
  remainder <- 0L
  for (digit in strsplit(numeric_text, "", fixed = TRUE)[[1L]]) {
    remainder <- (remainder * 10L + as.integer(digit)) %% 97L
  }
  identical(remainder, 1L)
}

.retry_call <- function(fn, retries = 0L, timeout_seconds = NULL) {
  last <- NULL
  for (attempt in seq_len(as.integer(retries) + 1L)) {
    last <- tryCatch(.with_elapsed_limit(fn, timeout_seconds), error = identity)
    if (!inherits(last, "error")) return(last)
  }
  last
}

.with_elapsed_limit <- function(fn, timeout_seconds = NULL) {
  if (is.null(timeout_seconds)) return(fn())
  setTimeLimit(elapsed = timeout_seconds, transient = TRUE)
  on.exit(setTimeLimit(cpu = Inf, elapsed = Inf, transient = FALSE), add = TRUE)
  fn()
}

.validate_count <- function(x, arg) {
  if (!is.numeric(x) || length(x) != 1L || is.na(x) || x < 0 || x != floor(x)) {
    cli::cli_abort("{.arg {arg}} must be a non-negative whole number.")
  }
  invisible(TRUE)
}

.validate_optional_positive <- function(x, arg) {
  if (is.null(x)) return(invisible(TRUE))
  if (!is.numeric(x) || length(x) != 1L || is.na(x) || !is.finite(x) || x <= 0) {
    cli::cli_abort("{.arg {arg}} must be a positive number or {.code NULL}.")
  }
  invisible(TRUE)
}
