#' Scan a prompt
#'
#' Scans user prompt text with rule-based, NLP, and optional semantic reviewer checks.
#' Findings retain OWASP LLM Top 10:2026 categories when known; see
#' <https://github.com/GenAI-Security-Project/GenAI-LLM-Top10>.
#'
#' @details
#' `scan_prompt()` is usually the first guardrail in a workflow. It normalizes
#' text with Unicode NFKC normalization, collapses whitespace, applies policy
#' rules, optionally applies the NLP intent rule, optionally asks a semantic
#' reviewer for JSON findings, calculates a `risk_score`, resolves an action,
#' and returns a [shieldr_report()].
#'
#' `checks = "rules"` uses deterministic policy rules. Built-in policies include
#' regular expressions and an NLP intent rule. `checks = "nlp"` runs only NLP
#' intent checks, using `tokenizers` for word tokenization and `SnowballC` for
#' stemming when those optional packages are installed. `checks = "llm"` uses
#' only the semantic reviewer when one is supplied. `checks = "both"` combines
#' policy rules with semantic review. Reviewer failures block by default;
#' `policy_controls(on_reviewer_error = "rules_only")` allows a rules-only fallback.
#'
#' Redaction replaces matched spans with `[REDACTED]`. Function-based findings
#' can influence score and action even when they do not provide exact spans.
#'
#' @param text Prompt text.
#' @param policy A `shieldr_policy` or built-in policy name such as `"comprehensive"`.
#' @param reviewer Optional reviewer function or object with `$chat()`.
#' @param checks One of `"rules"`, `"nlp"`, `"llm"`, or `"both"`.
#' @param redact Whether to redact matched spans in `text_clean`.
#' @param redaction Optional redaction strategy from [redaction_strategy()].
#'   Ignored when `redact = FALSE`.
#' @param scanners Optional scanner configuration from [scanner_options()].
#' @param show_tokens Whether to attach token counts when `ellmer` is available.
#' @param show_stats Show elapsed time, token estimate, network status, and
#'   transfer metrics when available.
#' @param stage Internal trust-boundary stage. Advanced callers should normally
#'   use the stage-specific public scanner instead.
#'
#' @return A `shieldr_report`.
#' @examples
#' scan_prompt("hello")
#' scan_prompt("patient has cancer password ak$1234567890", policy = "comprehensive")
#' scan_prompt("email neel@example.com", redaction = redaction_strategy("hash"))
#' scan_prompt("hello", show_tokens = TRUE)
#' @export
scan_prompt <- function(text,
                        policy = "enterprise_default",
                        reviewer = NULL,
                        checks = "rules",
                        redact = TRUE,
                        redaction = NULL,
                        scanners = scanner_options(),
                        show_tokens = FALSE,
                        stage = "prompt",
                        show_stats = FALSE) {
  stats <- .stats_begin(show_stats, "scan_prompt")
  on.exit(.stats_end(stats), add = TRUE)
  .stats_text_tokens(stats, text)
  .stats_track_reviewer(stats, reviewer, checks)
  .check_string(text, "text", allow_empty = TRUE)
  policy <- .as_policy(policy)
  checks <- .validate_checks(checks)
  if (!(is.logical(redact) && length(redact) == 1L && !is.na(redact))) {
    cli::cli_abort("{.arg redact} must be {.code TRUE} or {.code FALSE}.")
  }
  redaction <- .validate_redaction_strategy(redaction)
  scanners <- .validate_scanner_options(scanners)
  show_tokens <- .validate_show_tokens(show_tokens)
  .validate_reviewer_for_checks(reviewer, checks)
  .check_choice(stage, "stage", c("prompt", "context", "tool_call", "document"))

  text_norm <- .normalise_text(text)
  findings <- list()
  reviewer_errors <- list()
  findings <- c(findings, .run_scanners(text, text_norm, policy, scanners, stage = stage))

  if (checks %in% c("rules", "both")) {
    findings <- c(findings, .run_rules(text_norm, policy, stage = stage))
  } else if (identical(checks, "nlp")) {
    findings <- c(findings, .run_nlp(text_norm, policy))
  }
  if (checks %in% c("llm", "both") && !is.null(reviewer)) {
    semantic <- .semantic_review(text_norm, reviewer, policy$name, policy$controls)
    reviewer_errors <- c(reviewer_errors, attr(semantic, "reviewer_errors") %||% list())
    findings <- c(findings, semantic)
  }
  if (length(reviewer_errors) > 0L &&
      policy$controls$on_reviewer_error %in% c("block", "escalate")) {
    findings <- c(findings, list(.reviewer_failure_finding()))
  }

  findings <- .dedupe_findings(findings)
  risk_score <- .score_findings(findings)
  action <- .resolve_action(risk_score, findings, policy)
  text_clean <- if (isTRUE(redact)) .apply_redaction(text_norm, findings, redaction) else text_norm

  shieldr_report(
    action = action,
    text_clean = text_clean,
    findings = findings,
    risk_score = risk_score,
    policy = policy$name,
    checks = checks,
    tokens = if (isTRUE(show_tokens)) .count_tokens(text) else NULL,
    metadata = .report_metadata(
      stage = stage,
      policy_version = policy$version,
      policy_fingerprint = policy$fingerprint,
      decision_schema_version = policy$decision_schema_version,
      reviewer_errors = reviewer_errors,
      review_status = .review_status(checks, reviewer, reviewer_errors),
      reviewer_failure_action = if (length(reviewer_errors) > 0L) policy$controls$on_reviewer_error else NULL,
      scanners = scanners
    )
  )
}

.reviewer_failure_finding <- function() {
  .synthetic_finding(
    "llm02.reviewer.failure", "llm02", "critical",
    "Required semantic reviewer failed or returned invalid findings.",
    action = "block"
  )
}

.review_status <- function(checks, reviewer, errors) {
  if (!checks %in% c("llm", "both")) return("not_requested")
  if (is.null(reviewer)) return("not_configured")
  if (length(errors) > 0L) "failed" else "passed"
}

#' Preflight-check a prompt
#'
#' Backward-compatible alias for [scan_prompt()].
#'
#' @inheritParams scan_prompt
#' @param show_tokens Whether to attach token counts when `ellmer` is available.
#'
#' @return A `shieldr_report`.
#' @examples
#' preflight_check("hello")
#' preflight_check("hello", show_tokens = TRUE)
#' @export
preflight_check <- function(text,
                            policy = "enterprise_default",
                            reviewer = NULL,
                            checks = "rules",
                            redact = TRUE,
                            redaction = NULL,
                            scanners = scanner_options(),
                            show_tokens = FALSE,
                            show_stats = FALSE) {
  stats <- .stats_begin(show_stats, "preflight_check")
  on.exit(.stats_end(stats), add = TRUE)
  .stats_text_tokens(stats, text)
  .stats_track_reviewer(stats, reviewer, checks)
  scan_prompt(
    text = text,
    policy = policy,
    reviewer = reviewer,
    checks = checks,
    redact = redact,
    redaction = redaction,
    scanners = scanners,
    show_tokens = show_tokens
  )
}

#' Run policy rules on text
#'
#' Applies every rule in a policy and returns raw finding lists.
#'
#' @details
#' Regex rules are matched with `gregexpr(..., perl = TRUE)`. Function rules
#' receive the full text and are coerced into finding objects. The helper
#' attaches a `risk_score` attribute to the finding list, but callers typically
#' recompute the score after adding semantic or synthetic findings.
#'
#' @param text Normalised text.
#' @param policy A `shieldr_policy` or built-in policy name such as `"comprehensive"`.
#'
#' @return A list of finding lists.
#' @keywords internal
.run_rules <- function(text, policy, stage = NULL) {
  .check_string(text, "text", allow_empty = TRUE)
  .check_policy(policy)

  findings <- list()
  for (rule in policy$rules) {
    if (!is.null(stage) && !stage %in% (rule$stages %||% c("prompt", "context", "output", "tool_call", "tool_output", "document"))) next
    if (!is.null(rule$pattern)) {
      matches <- tryCatch(
        gregexpr(rule$pattern, text, perl = TRUE),
        error = function(e) {
          cli::cli_warn("Rule {.val {rule$id}} has an invalid regular expression and was skipped.")
          structure(-1L, match.length = -1L)
        }
      )
      starts <- as.integer(matches[[1]])
      lengths <- as.integer(attr(matches[[1]], "match.length"))
      if (length(starts) == 0L || identical(starts[[1]], -1L)) {
        next
      }
      ends <- starts + lengths - 1L
      for (i in seq_along(starts)) {
        finding <- .finding(
          rule = rule,
          match = substr(text, starts[[i]], ends[[i]]),
          start = starts[[i]],
          end = ends[[i]],
          source = "rules"
        )
        finding$stage <- stage
        findings[[length(findings) + 1L]] <- finding
      }
    } else if (!is.null(rule$fn)) {
      result <- rule$fn(text)
      fn_findings <- .coerce_fn_findings(result, rule)
      fn_findings <- lapply(fn_findings, function(finding) { finding$stage <- stage; finding })
      findings <- c(findings, fn_findings)
    }
  }

  attr(findings, "risk_score") <- .score_findings(findings)
  findings
}

.run_nlp <- function(text, policy) {
  .check_string(text, "text", allow_empty = TRUE)
  .check_policy(policy)

  rules <- Filter(.is_nlp_rule, policy$rules)
  ids <- vapply(rules, `[[`, character(1), "id")
  if (!"llm01.nlp.intent" %in% ids) {
    rules <- c(rules, list(rule_nlp_intent()))
  }

  nlp_policy <- shieldr_policy(
    name = policy$name,
    rules = rules,
    thresholds = policy$thresholds,
    trusted_sources = policy$trusted_sources,
    controls = policy$controls,
    version = policy$version
  )
  .run_rules(text, nlp_policy)
}

.is_nlp_rule <- function(rule) {
  inherits(rule, "shieldr_rule") && grepl("\\.nlp\\.", rule$id)
}

#' Resolve final action from risk and findings
#'
#' Converts a report score and findings into `allow`, `redact`, or `block`.
#'
#' @details
#' Resolution is conservative. A critical finding, explicit block action, or
#' score above `policy$thresholds$block_at` returns `block`. Otherwise, a
#' redaction finding or score at or above `policy$thresholds$redact_at` returns
#' `redact`. All other cases return `allow`.
#'
#' @param risk_score Numeric risk score.
#' @param findings Finding list.
#' @param policy A `shieldr_policy`.
#'
#' @return A string action.
#' @keywords internal
.resolve_action <- function(risk_score, findings, policy) {
  .check_number_between(risk_score, "risk_score", 0, 1)
  .check_policy(policy)
  severities <- vapply(findings, function(finding) finding$severity %||% "low", character(1))
  actions <- vapply(findings, function(finding) finding$action %||% "redact", character(1))

  if (any(severities == "critical") || any(actions == "block") || risk_score > policy$thresholds$block_at) {
    return("block")
  }
  if (any(actions == "redact") || risk_score >= policy$thresholds$redact_at) {
    return("redact")
  }
  "allow"
}

#' Apply span redaction
#'
#' Replaces matched finding spans using a configured redaction strategy.
#'
#' @details
#' Findings can overlap, especially when one rule catches a broad credential
#' phrase and another catches a narrower token. This helper sorts and merges
#' spans before replacement. Replacements are applied from the end of the string
#' toward the beginning so offsets remain stable.
#'
#' @param text Text to redact.
#' @param findings Finding list.
#' @param redaction Redaction strategy from [redaction_strategy()].
#'
#' @return Redacted text.
#' @keywords internal
.apply_redaction <- function(text, findings, redaction = NULL) {
  redaction <- .validate_redaction_strategy(redaction)
  spans <- lapply(findings, function(finding) {
    if (is.null(finding$start) || is.null(finding$end)) {
      return(NULL)
    }
    if (!is.numeric(finding$start) || !is.numeric(finding$end)) {
      return(NULL)
    }
    if (is.na(finding$start) || is.na(finding$end)) {
      return(NULL)
    }
    c(start = as.integer(finding$start), end = as.integer(finding$end))
  })
  spans <- Filter(Negate(is.null), spans)
  if (length(spans) == 0L) {
    return(text)
  }

  spans <- do.call(rbind, spans)
  spans <- spans[order(spans[, "start"], spans[, "end"]), , drop = FALSE]
  merged <- matrix(integer(), ncol = 2L, dimnames = list(NULL, c("start", "end")))
  for (i in seq_len(nrow(spans))) {
    span <- spans[i, ]
    if (nrow(merged) == 0L || span[["start"]] > merged[nrow(merged), "end"] + 1L) {
      merged <- rbind(merged, span)
    } else {
      merged[nrow(merged), "end"] <- max(merged[nrow(merged), "end"], span[["end"]])
    }
  }

  out <- text
  for (i in rev(seq_len(nrow(merged)))) {
    start <- merged[i, "start"]
    end <- merged[i, "end"]
    if (start < 1L || end < start || start > nchar(out)) {
      next
    }
    end <- min(end, nchar(out))
    value <- substr(out, start, end)
    replacement <- .redaction_replacement(value, redaction)
    before <- if (start > 1L) substr(out, 1L, start - 1L) else ""
    after <- if (end < nchar(out)) substr(out, end + 1L, nchar(out)) else ""
    out <- paste0(before, replacement, after)
  }
  out
}

#' Run semantic reviewer checks
#'
#' Asks a reviewer model or function for JSON findings.
#'
#' @details
#' The reviewer prompt asks for an array of objects containing `rule_id`,
#' `owasp`, `severity`, and `description`. Reviewers may also return
#' `confidence`, `evidence`, `recommended_action`, and `span`. `span` may be a
#' two-element numeric vector or an object with `start` and `end`. The reviewer
#' can be a function or an object with `$chat()`. Malformed JSON and call
#' failures are recorded and block by default; policy controls may escalate or
#' explicitly allow a deterministic rules-only fallback.
#' Custom reviewer instructions should be added by wrapping the reviewer and
#' prepending context before delegating to the model, while keeping this JSON
#' schema intact.
#' Structured parse and schema errors are attached to the report metadata by the
#' public scanner wrappers.
#'
#' @param text Text to review.
#' @param reviewer Function or chat object.
#' @param policy_name Policy name.
#'
#' @return A list of finding lists.
#' @keywords internal
.semantic_review <- function(text, reviewer, policy_name, controls = policy_controls()) {
  prompt <- paste(
    .shieldr_reviewer_prompt,
    paste0("Policy: ", policy_name),
    "Text:",
    text,
    sep = "\n"
  )

  errors <- list()
  controls <- .validate_policy_controls(controls)
  response <- .retry_call(
    function() .call_reviewer(reviewer, prompt),
    retries = controls$reviewer_retries,
    timeout_seconds = controls$reviewer_timeout_seconds
  )
  if (inherits(response, "error")) {
    error_type <- if (grepl("time limit|timeout|timed out", conditionMessage(response), ignore.case = TRUE)) "timeout" else "call_failed"
    errors[[length(errors) + 1L]] <- .reviewer_error(error_type, conditionMessage(response))
    cli::cli_warn("Semantic reviewer failed; applying {.val {controls$on_reviewer_error}} policy.")
    return(.with_reviewer_errors(list(), errors))
  }
  if (is.null(response)) {
    errors[[length(errors) + 1L]] <- .reviewer_error("empty_response", "Reviewer returned NULL.")
    return(.with_reviewer_errors(list(), errors))
  }
  response <- paste(as.character(response), collapse = "\n")

  json_text <- .extract_json_payload(response)
  parsed <- tryCatch(
    jsonlite::fromJSON(json_text, simplifyVector = FALSE),
    error = function(e) {
      errors[[length(errors) + 1L]] <<- .reviewer_error(
        "malformed_json",
        conditionMessage(e),
        response_excerpt = substr(response, 1L, 500L)
      )
      cli::cli_warn("Semantic reviewer returned malformed JSON; ignoring semantic findings.")
      NULL
    }
  )
  if (is.null(parsed) || length(parsed) == 0L) {
    return(.with_reviewer_errors(list(), errors))
  }
  if (is.list(parsed) && !is.null(parsed$findings)) {
    parsed <- parsed$findings
  }
  if (is.data.frame(parsed)) {
    parsed <- lapply(seq_len(nrow(parsed)), function(i) as.list(parsed[i, , drop = FALSE]))
  }
  if (!is.list(parsed)) {
    errors[[length(errors) + 1L]] <- .reviewer_error(
      "invalid_schema",
      "Reviewer JSON must be an array of finding objects or an object with a findings array."
    )
    return(.with_reviewer_errors(list(), errors))
  }

  out <- list()
  for (i in seq_along(parsed)) {
    item <- parsed[[i]]
    if (!is.list(item)) {
      errors[[length(errors) + 1L]] <- .reviewer_error(
        "invalid_finding",
        "Reviewer finding was not an object.",
        finding_index = i
      )
      next
    }
    coerced <- .coerce_reviewer_finding(item, i)
    errors <- c(errors, coerced$errors)
    out[[length(out) + 1L]] <- coerced$finding
  }
  .with_reviewer_errors(out, errors)
}

.coerce_reviewer_finding <- function(item, index) {
  errors <- list()

  severity <- tolower(.reviewer_scalar(item$severity, "medium"))
  if (!severity %in% .shieldr_severities()) {
    errors[[length(errors) + 1L]] <- .reviewer_error(
      "invalid_severity",
      "Reviewer severity was not one of low, medium, high, or critical; using medium.",
      finding_index = index,
      value = as.character(item$severity %||% NA_character_)
    )
    severity <- "medium"
  }

  recommended_action <- tolower(.reviewer_scalar(item$recommended_action %||% item$action, NA_character_))
  if (!is.na(recommended_action) && nzchar(recommended_action) && !recommended_action %in% .shieldr_rule_actions()) {
    errors[[length(errors) + 1L]] <- .reviewer_error(
      "invalid_recommended_action",
      "Reviewer recommended_action was not one of allow, redact, or block; deriving action from severity.",
      finding_index = index,
      value = recommended_action
    )
    recommended_action <- NA_character_
  }
  action <- if (!is.na(recommended_action) && nzchar(recommended_action)) {
    recommended_action
  } else if (identical(severity, "critical")) {
    "block"
  } else {
    "redact"
  }

  confidence <- NA_real_
  if (!is.null(item$confidence) && length(item$confidence) > 0L) {
    confidence <- tryCatch(suppressWarnings(as.numeric(item$confidence[[1]])), error = function(e) NA_real_)
    if (length(confidence) != 1L || is.na(confidence) || confidence < 0 || confidence > 1) {
      errors[[length(errors) + 1L]] <- .reviewer_error(
        "invalid_confidence",
        "Reviewer confidence must be a number between 0 and 1; dropping confidence.",
        finding_index = index
      )
      confidence <- NA_real_
    }
  }

  span <- .coerce_reviewer_span(item$span %||% NULL)
  if (isTRUE(span$invalid)) {
    errors[[length(errors) + 1L]] <- .reviewer_error(
      "invalid_span",
      "Reviewer span must contain numeric start and end values; dropping span.",
      finding_index = index
    )
  }

  rule_id <- .reviewer_scalar(item$rule_id, "llm.semantic.review")
  if (!grepl("^[A-Za-z0-9_.-]{1,80}$", rule_id)) {
    errors[[length(errors) + 1L]] <- .reviewer_error("invalid_rule_id", "Reviewer rule_id was invalid.", finding_index = index)
    rule_id <- "llm.semantic.review"
  }
  owasp <- tolower(.reviewer_scalar(item$owasp, NA_character_))
  if (!is.na(owasp) && !owasp %in% sprintf("llm%02d", 1:10)) {
    errors[[length(errors) + 1L]] <- .reviewer_error("invalid_owasp", "Reviewer OWASP 2026 category was invalid.", finding_index = index)
    owasp <- NA_character_
  }
  finding <- list(
    rule_id = rule_id,
    owasp = owasp,
    severity = severity,
    action = action,
    description = .reviewer_scalar(item$description, "Semantic reviewer finding."),
    match = .reviewer_scalar(item$match %||% item$evidence, NA_character_),
    start = span$start,
    end = span$end,
    source = "llm",
    confidence = confidence,
    evidence = .reviewer_scalar(item$evidence, NA_character_),
    recommended_action = if (is.na(recommended_action)) NA_character_ else recommended_action
  )

  list(finding = finding, errors = errors)
}

.reviewer_scalar <- function(x, default) {
  if (is.null(x) || length(x) == 0L) return(default)
  value <- tryCatch(as.character(x[[1L]]), error = function(e) character())
  if (length(value) != 1L || is.na(value)) default else value
}

.coerce_reviewer_span <- function(span) {
  out <- list(start = NA_integer_, end = NA_integer_, invalid = FALSE)
  if (is.null(span)) {
    return(out)
  }
  values <- if (is.list(span) && !is.null(span$start) && !is.null(span$end)) {
    c(span$start, span$end)
  } else {
    unlist(span, use.names = FALSE)
  }
  values <- suppressWarnings(as.integer(values))
  if (length(values) < 2L || any(is.na(values[1:2])) || values[[1]] < 1L || values[[2]] < values[[1]]) {
    out$invalid <- TRUE
    return(out)
  }
  out$start <- values[[1]]
  out$end <- values[[2]]
  out
}

.with_reviewer_errors <- function(findings, errors) {
  attr(findings, "reviewer_errors") <- errors
  findings
}

.reviewer_error <- function(type, message, ...) {
  details <- list(...)
  details <- details[!vapply(details, is.null, logical(1))]
  c(
    list(
      type = type,
      message = message,
      timestamp = .now_iso()
    ),
    details
  )
}

.extract_json_payload <- function(response) {
  text <- trimws(paste(as.character(response), collapse = "\n"))
  fenced <- regexec("```(?:json)?\\s*([\\s\\S]*?)\\s*```", text, ignore.case = TRUE, perl = TRUE)
  hit <- regmatches(text, fenced)[[1]]
  if (length(hit) >= 2L) {
    return(trimws(hit[[2]]))
  }

  starts <- c(
    array = regexpr("\\[", text, perl = TRUE)[[1]],
    object = regexpr("\\{", text, perl = TRUE)[[1]]
  )
  starts <- starts[starts > 0L]
  if (length(starts) == 0L) {
    return(text)
  }

  array_ends <- gregexpr("\\]", text, perl = TRUE)[[1]]
  object_ends <- gregexpr("\\}", text, perl = TRUE)[[1]]
  ends <- c(array_ends[array_ends > 0L], object_ends[object_ends > 0L])
  if (length(ends) == 0L) {
    return(text)
  }

  start <- min(starts)
  end <- max(ends)
  if (end >= start) {
    return(trimws(substr(text, start, end)))
  }
  text
}

# Effective confusable map. Hexadecimal names avoid source-encoding warnings
# under non-UTF-8 R locales; names are converted to Unicode at load time.
.homoglyph_map <- c(
  "0410" = "A", "0391" = "A", "FF21" = "A",
  "0430" = "a", "03B1" = "a", "FF41" = "a",
  "0412" = "B", "0392" = "B", "FF22" = "B",
  "0421" = "C", "03F9" = "C", "FF23" = "C",
  "0441" = "c", "03F2" = "c", "FF43" = "c",
  "0415" = "E", "0395" = "E", "FF25" = "E",
  "0435" = "e", "03B5" = "e", "FF45" = "e",
  "041D" = "H", "0397" = "H", "FF28" = "H",
  "04BB" = "h", "FF48" = "h",
  "0406" = "I", "0399" = "I", "FF29" = "I",
  "0456" = "i", "03B9" = "i", "FF49" = "i",
  "0408" = "J", "FF2A" = "J",
  "0458" = "j", "FF4A" = "j",
  "041A" = "K", "039A" = "K", "FF2B" = "K",
  "043A" = "k", "03BA" = "k", "FF4B" = "k",
  "041C" = "M", "039C" = "M", "FF2D" = "M",
  "043C" = "m", "03BC" = "m", "FF4D" = "m",
  "039D" = "N", "FF2E" = "N",
  "043D" = "h", "03BD" = "v", "FF4E" = "n",
  "041E" = "O", "039F" = "O", "FF2F" = "O",
  "043E" = "o", "03BF" = "o", "FF4F" = "o",
  "0420" = "P", "03A1" = "P", "FF30" = "P",
  "0440" = "p", "03C1" = "p", "FF50" = "p",
  "0405" = "S", "FF33" = "S",
  "0455" = "s", "FF53" = "s",
  "0422" = "T", "03A4" = "T", "FF34" = "T",
  "0442" = "t", "03C4" = "t", "FF54" = "t",
  "0425" = "X", "03A7" = "X", "FF38" = "X",
  "0445" = "x", "03C7" = "x", "FF58" = "x",
  "0423" = "Y", "03A5" = "Y", "FF39" = "Y",
  "0443" = "y", "03C5" = "y", "FF59" = "y"
)
names(.homoglyph_map) <- vapply(names(.homoglyph_map), function(hex) {
  intToUtf8(strtoi(hex, base = 16L))
}, character(1))

.normalise_text <- function(text, collapse_whitespace = TRUE, collapse_delimited = TRUE) {
  text <- stringi::stri_trans_nfkc(text)
  text <- stringi::stri_replace_all_regex(text, "\\p{Cf}+", "", vectorize_all = FALSE)
  if (isTRUE(collapse_whitespace)) {
    text <- gsub("\\s+", " ", trimws(text), perl = TRUE)
  }
  for (i in seq_along(.homoglyph_map)) {
    text <- stringi::stri_replace_all_fixed(
      text,
      names(.homoglyph_map)[[i]],
      .homoglyph_map[[i]],
      vectorize_all = FALSE
    )
  }
  if (isTRUE(collapse_delimited)) {
    text <- .collapse_delimited_words(text)
  }
  text
}

.collapse_delimited_words <- function(text) {
  matches <- gregexpr("\\b(?:[A-Za-z][ ._-]){2,}[A-Za-z]\\b", text, perl = TRUE)[[1]]
  if (length(matches) == 0L || identical(matches[[1]], -1L)) {
    return(text)
  }
  lengths <- as.integer(attr(matches, "match.length"))
  out <- text
  for (i in rev(seq_along(matches))) {
    start <- as.integer(matches[[i]])
    end <- start + lengths[[i]] - 1L
    raw <- substr(out, start, end)
    collapsed <- gsub("(?<=[a-zA-Z])([ ._-](?=[a-zA-Z]))+", "", raw, perl = TRUE)
    before <- if (start > 1L) substr(out, 1L, start - 1L) else ""
    after <- if (end < nchar(out)) substr(out, end + 1L, nchar(out)) else ""
    out <- paste0(before, collapsed, after)
  }
  out
}

.validate_checks <- function(checks) {
  .check_choice(checks, "checks", c("rules", "nlp", "llm", "both"))
  checks
}

.validate_show_tokens <- function(show_tokens) {
  if (!(is.logical(show_tokens) && length(show_tokens) == 1L && !is.na(show_tokens))) {
    cli::cli_abort("{.arg show_tokens} must be {.code TRUE} or {.code FALSE}.")
  }
  isTRUE(show_tokens)
}

.validate_reviewer <- function(reviewer) {
  if (is.null(reviewer)) {
    return(invisible(TRUE))
  }
  if (!is.function(reviewer) && !.has_chat_method(reviewer)) {
    cli::cli_abort("{.arg reviewer} must be a function, an object with {.code $chat()}, or {.code NULL}.")
  }
  invisible(TRUE)
}

.validate_reviewer_for_checks <- function(reviewer, checks) {
  .validate_reviewer(reviewer)
  if (identical(checks, "llm") && is.null(reviewer)) {
    cli::cli_abort(
      "{.arg reviewer} must be supplied when {.arg checks} is {.val llm}; otherwise no semantic check can run."
    )
  }
  if (identical(checks, "both") && is.null(reviewer)) {
    cli::cli_warn(
      "{.arg checks} is {.val both}, but no {.arg reviewer} was supplied; continuing with deterministic checks only."
    )
  }
  invisible(TRUE)
}

.call_reviewer <- function(reviewer, prompt) {
  if (is.function(reviewer)) {
    return(reviewer(prompt))
  }
  reviewer$chat(prompt)
}

.finding <- function(rule,
                     match = NA_character_,
                     start = NA_integer_,
                     end = NA_integer_,
                     source = "rules") {
  list(
    rule_id = rule$id,
    owasp = rule$owasp %||% NA_character_,
    severity = rule$severity,
    action = rule$action,
    description = rule$description,
    match = match,
    start = start,
    end = end,
    source = source,
    confidence = rule$confidence %||% NA_real_
  )
}

.coerce_fn_findings <- function(result, rule) {
  if (is.null(result) || identical(result, FALSE)) {
    return(list())
  }
  if (identical(result, TRUE)) {
    return(list(.finding(rule, source = "rules")))
  }
  if (is.data.frame(result)) {
    result <- lapply(seq_len(nrow(result)), function(i) as.list(result[i, , drop = FALSE]))
  }
  if (is.list(result) && !is.null(result$rule_id)) {
    result <- list(result)
  }
  if (!is.list(result)) {
    return(list(.finding(rule, match = as.character(result), source = "rules")))
  }

  out <- list()
  for (item in result) {
    if (!is.list(item)) {
      out[[length(out) + 1L]] <- .finding(rule, match = as.character(item), source = "rules")
      next
    }
    out[[length(out) + 1L]] <- list(
      rule_id = as.character(item$rule_id %||% rule$id),
      owasp = tolower(as.character(item$owasp %||% rule$owasp %||% NA_character_)),
      severity = tolower(as.character(item$severity %||% rule$severity)),
      action = tolower(as.character(item$action %||% rule$action)),
      description = as.character(item$description %||% rule$description),
      match = as.character(item$match %||% NA_character_),
      start = as.integer(item$start %||% NA_integer_),
      end = as.integer(item$end %||% NA_integer_),
      source = as.character(item$source %||% "rules")
    )
  }
  out
}

.score_findings <- function(findings) {
  if (length(findings) == 0L) {
    return(0)
  }
  scores <- vapply(findings, function(finding) {
    .severity_score(tolower(finding$severity %||% "low"))
  }, numeric(1))
  synthetic <- vapply(findings, function(finding) isTRUE(finding$synthetic), logical(1))
  rule_score <- .score_evidence_findings(findings[!synthetic], scores[!synthetic])
  synthetic_score <- sum(scores[synthetic])
  min(rule_score + min(synthetic_score, 0.3), 1)
}

.score_evidence_findings <- function(findings, scores) {
  if (length(findings) == 0L) {
    return(0)
  }

  starts <- vapply(findings, function(finding) as.integer(finding$start %||% NA_integer_), integer(1))
  ends <- vapply(findings, function(finding) as.integer(finding$end %||% NA_integer_), integer(1))
  has_span <- !is.na(starts) & !is.na(ends) & starts >= 1L & ends >= starts
  score <- sum(scores[!has_span])
  if (!any(has_span)) {
    return(score)
  }

  keys <- vapply(findings, function(finding) {
    paste(
      finding$source %||% "",
      finding$owasp %||% "",
      finding$action %||% "",
      sep = "\r"
    )
  }, character(1))

  for (key in unique(keys[has_span])) {
    idx <- which(has_span & keys == key)
    ord <- order(starts[idx], ends[idx])
    idx <- idx[ord]
    group_end <- ends[idx[[1]]]
    group_score <- scores[idx[[1]]]

    if (length(idx) > 1L) {
      for (i in idx[-1L]) {
        if (starts[[i]] <= group_end) {
          group_end <- max(group_end, ends[[i]])
          group_score <- max(group_score, scores[[i]])
        } else {
          score <- score + group_score
          group_end <- ends[[i]]
          group_score <- scores[[i]]
        }
      }
    }
    score <- score + group_score
  }

  score
}

.dedupe_findings <- function(findings) {
  if (length(findings) == 0L) {
    return(list())
  }
  keys <- vapply(findings, function(finding) {
    paste(
      finding$rule_id %||% "",
      finding$start %||% "",
      finding$end %||% "",
      finding$source %||% "",
      sep = "\r"
    )
  }, character(1))
  findings[!duplicated(keys)]
}
