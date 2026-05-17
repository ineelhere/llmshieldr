#' Scan a prompt
#'
#' Scans user prompt text with rule-based, NLP, and optional semantic reviewer checks.
#' Findings retain OWASP LLM Top 10 categories when known; see
#' <https://genai.owasp.org/llm-top-10/>.
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
#' policy rules with semantic review. If LLM review returns malformed JSON, the
#' function warns and continues with the findings it already has.
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
                        show_tokens = FALSE) {
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

  text_norm <- .normalise_text(text)
  findings <- list()
  reviewer_errors <- list()
  findings <- c(findings, .run_scanners(text, text_norm, policy, scanners, stage = "prompt"))

  if (checks %in% c("rules", "both")) {
    findings <- c(findings, .run_rules(text_norm, policy))
  } else if (identical(checks, "nlp")) {
    findings <- c(findings, .run_nlp(text_norm, policy))
  }
  if (checks %in% c("llm", "both") && !is.null(reviewer)) {
    semantic <- .semantic_review(text_norm, reviewer, policy$name)
    reviewer_errors <- c(reviewer_errors, attr(semantic, "reviewer_errors") %||% list())
    findings <- c(findings, semantic)
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
      stage = "prompt",
      reviewer_errors = reviewer_errors,
      scanners = scanners
    )
  )
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
                            show_tokens = FALSE) {
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
.run_rules <- function(text, policy) {
  .check_string(text, "text", allow_empty = TRUE)
  .check_policy(policy)

  findings <- list()
  for (rule in policy$rules) {
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
        findings[[length(findings) + 1L]] <- .finding(
          rule = rule,
          match = substr(text, starts[[i]], ends[[i]]),
          start = starts[[i]],
          end = ends[[i]],
          source = "rules"
        )
      }
    } else if (!is.null(rule$fn)) {
      result <- rule$fn(text)
      findings <- c(findings, .coerce_fn_findings(result, rule))
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
    trusted_sources = policy$trusted_sources
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
#' can be a function or an object with `$chat()`. Malformed JSON is treated as a
#' soft failure because deterministic rule findings should still be usable.
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
.semantic_review <- function(text, reviewer, policy_name) {
  prompt <- paste(
    .shieldr_reviewer_prompt,
    paste0("Policy: ", policy_name),
    "Text:",
    text,
    sep = "\n"
  )

  errors <- list()
  response <- tryCatch(
    .call_reviewer(reviewer, prompt),
    error = function(e) {
      errors[[length(errors) + 1L]] <<- .reviewer_error(
        "call_failed",
        conditionMessage(e)
      )
      cli::cli_warn("Semantic reviewer failed; continuing with rule findings only.")
      NULL
    }
  )
  if (is.null(response)) {
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

  severity <- tolower(as.character(item$severity %||% "medium"))
  if (!severity %in% .shieldr_severities()) {
    errors[[length(errors) + 1L]] <- .reviewer_error(
      "invalid_severity",
      "Reviewer severity was not one of low, medium, high, or critical; using medium.",
      finding_index = index,
      value = as.character(item$severity %||% NA_character_)
    )
    severity <- "medium"
  }

  recommended_action <- tolower(as.character(item$recommended_action %||% item$action %||% NA_character_))
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
    confidence <- suppressWarnings(as.numeric(item$confidence[[1]]))
    if (is.na(confidence) || confidence < 0 || confidence > 1) {
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

  finding <- list(
    rule_id = as.character(item$rule_id %||% "llm.semantic.review"),
    owasp = if (is.null(item$owasp)) NA_character_ else tolower(as.character(item$owasp)),
    severity = severity,
    action = action,
    description = as.character(item$description %||% "Semantic reviewer finding."),
    match = as.character(item$match %||% item$evidence %||% NA_character_),
    start = span$start,
    end = span$end,
    source = "llm",
    confidence = confidence,
    evidence = as.character(item$evidence %||% NA_character_),
    recommended_action = if (is.na(recommended_action)) NA_character_ else recommended_action
  )

  list(finding = finding, errors = errors)
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

# Effective confusable map. Unicode escapes keep this source file ASCII-safe.
.homoglyph_map <- c(
  "\u0410" = "A", "\u0391" = "A", "\uFF21" = "A",
  "\u0430" = "a", "\u03B1" = "a", "\uFF41" = "a",
  "\u0412" = "B", "\u0392" = "B", "\uFF22" = "B",
  "\u0421" = "C", "\u03F9" = "C", "\uFF23" = "C",
  "\u0441" = "c", "\u03F2" = "c", "\uFF43" = "c",
  "\u0415" = "E", "\u0395" = "E", "\uFF25" = "E",
  "\u0435" = "e", "\u03B5" = "e", "\uFF45" = "e",
  "\u041D" = "H", "\u0397" = "H", "\uFF28" = "H",
  "\u04BB" = "h", "\uFF48" = "h",
  "\u0406" = "I", "\u0399" = "I", "\uFF29" = "I",
  "\u0456" = "i", "\u03B9" = "i", "\uFF49" = "i",
  "\u0408" = "J", "\uFF2A" = "J",
  "\u0458" = "j", "\uFF4A" = "j",
  "\u041A" = "K", "\u039A" = "K", "\uFF2B" = "K",
  "\u043A" = "k", "\u03BA" = "k", "\uFF4B" = "k",
  "\u041C" = "M", "\u039C" = "M", "\uFF2D" = "M",
  "\u043C" = "m", "\u03BC" = "m", "\uFF4D" = "m",
  "\u039D" = "N", "\uFF2E" = "N",
  "\u043D" = "h", "\u03BD" = "v", "\uFF4E" = "n",
  "\u041E" = "O", "\u039F" = "O", "\uFF2F" = "O",
  "\u043E" = "o", "\u03BF" = "o", "\uFF4F" = "o",
  "\u0420" = "P", "\u03A1" = "P", "\uFF30" = "P",
  "\u0440" = "p", "\u03C1" = "p", "\uFF50" = "p",
  "\u0405" = "S", "\uFF33" = "S",
  "\u0455" = "s", "\uFF53" = "s",
  "\u0422" = "T", "\u03A4" = "T", "\uFF34" = "T",
  "\u0442" = "t", "\u03C4" = "t", "\uFF54" = "t",
  "\u0425" = "X", "\u03A7" = "X", "\uFF38" = "X",
  "\u0445" = "x", "\u03C7" = "x", "\uFF58" = "x",
  "\u0423" = "Y", "\u03A5" = "Y", "\uFF39" = "Y",
  "\u0443" = "y", "\u03C5" = "y", "\uFF59" = "y"
)

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
    source = source
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
