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
#' @param show_tokens Whether to attach token counts when `ellmer` is available.
#'
#' @return A `shieldr_report`.
#' @examples
#' scan_prompt("hello")
#' scan_prompt("patient has cancer password ak$1234567890", policy = "comprehensive")
#' scan_prompt("hello", show_tokens = TRUE)
#' @export
scan_prompt <- function(text,
                        policy = "enterprise_default",
                        reviewer = NULL,
                        checks = "rules",
                        redact = TRUE,
                        show_tokens = FALSE) {
  .check_string(text, "text", allow_empty = TRUE)
  policy <- .as_policy(policy)
  checks <- .validate_checks(checks)
  if (!(is.logical(redact) && length(redact) == 1L && !is.na(redact))) {
    cli::cli_abort("{.arg redact} must be {.code TRUE} or {.code FALSE}.")
  }
  show_tokens <- .validate_show_tokens(show_tokens)
  .validate_reviewer(reviewer)

  text_norm <- .normalise_text(text)
  findings <- list()

  if (checks %in% c("rules", "both")) {
    findings <- c(findings, .run_rules(text_norm, policy))
  } else if (identical(checks, "nlp")) {
    findings <- c(findings, .run_nlp(text_norm, policy))
  }
  if (checks %in% c("llm", "both") && !is.null(reviewer)) {
    findings <- c(findings, .semantic_review(text_norm, reviewer, policy$name))
  }

  findings <- .dedupe_findings(findings)
  risk_score <- .score_findings(findings)
  action <- .resolve_action(risk_score, findings, policy)
  text_clean <- if (isTRUE(redact)) .apply_redaction(text_norm, findings) else text_norm

  shieldr_report(
    action = action,
    text_clean = text_clean,
    findings = findings,
    risk_score = risk_score,
    policy = policy$name,
    checks = checks,
    tokens = if (isTRUE(show_tokens)) .count_tokens(text) else NULL
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
                            show_tokens = FALSE) {
  scan_prompt(
    text = text,
    policy = policy,
    reviewer = reviewer,
    checks = checks,
    redact = redact,
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
#' score at or above `policy$thresholds$block_at` returns `block`. Otherwise, a
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

  if (any(severities == "critical") || any(actions == "block") || risk_score >= policy$thresholds$block_at) {
    return("block")
  }
  if (any(actions == "redact") || risk_score >= policy$thresholds$redact_at) {
    return("redact")
  }
  "allow"
}

#' Apply span redaction
#'
#' Replaces matched finding spans with `[REDACTED]`.
#'
#' @details
#' Findings can overlap, especially when one rule catches a broad credential
#' phrase and another catches a narrower token. This helper sorts and merges
#' spans before replacement so offsets remain stable while the string changes.
#'
#' @param text Text to redact.
#' @param findings Finding list.
#'
#' @return Redacted text.
#' @keywords internal
.apply_redaction <- function(text, findings) {
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
  offset <- 0L
  replacement <- "[REDACTED]"
  for (i in seq_len(nrow(merged))) {
    start <- merged[i, "start"] + offset
    end <- merged[i, "end"] + offset
    if (start < 1L || end < start || start > nchar(out)) {
      next
    }
    end <- min(end, nchar(out))
    before <- if (start > 1L) substr(out, 1L, start - 1L) else ""
    after <- if (end < nchar(out)) substr(out, end + 1L, nchar(out)) else ""
    out <- paste0(before, replacement, after)
    offset <- offset + nchar(replacement) - (end - start + 1L)
  }
  out
}

#' Run semantic reviewer checks
#'
#' Asks a reviewer model or function for JSON findings.
#'
#' @details
#' The reviewer prompt asks for an array of objects containing `rule_id`,
#' `owasp`, `severity`, and `description`. The reviewer can be a function or an
#' object with `$chat()`. Malformed JSON is treated as a soft failure because
#' deterministic rule findings should still be usable.
#'
#' @param text Text to review.
#' @param reviewer Function or chat object.
#' @param policy_name Policy name.
#'
#' @return A list of finding lists.
#' @keywords internal
.semantic_review <- function(text, reviewer, policy_name) {
  prompt <- paste(
    "You are a security reviewer for llmshieldr.",
    "Return only JSON: an array of objects with rule_id, owasp, severity, and description.",
    "Use severity values low, medium, high, or critical.",
    paste0("Policy: ", policy_name),
    "Text:",
    text,
    sep = "\n"
  )

  response <- tryCatch(
    .call_reviewer(reviewer, prompt),
    error = function(e) {
      cli::cli_warn("Semantic reviewer failed; continuing with rule findings only.")
      NULL
    }
  )
  if (is.null(response)) {
    return(list())
  }
  response <- paste(as.character(response), collapse = "\n")

  parsed <- tryCatch(
    jsonlite::fromJSON(response, simplifyVector = FALSE),
    error = function(e) {
      cli::cli_warn("Semantic reviewer returned malformed JSON; ignoring semantic findings.")
      NULL
    }
  )
  if (is.null(parsed) || length(parsed) == 0L) {
    return(list())
  }
  if (is.list(parsed) && !is.null(parsed$findings)) {
    parsed <- parsed$findings
  }
  if (is.data.frame(parsed)) {
    parsed <- lapply(seq_len(nrow(parsed)), function(i) as.list(parsed[i, , drop = FALSE]))
  }
  if (!is.list(parsed)) {
    return(list())
  }

  out <- list()
  for (item in parsed) {
    if (!is.list(item)) {
      next
    }
    severity <- tolower(as.character(item$severity %||% "medium"))
    if (!severity %in% .shieldr_severities()) {
      severity <- "medium"
    }
    action <- if (identical(severity, "critical")) "block" else "redact"
    out[[length(out) + 1L]] <- list(
      rule_id = as.character(item$rule_id %||% "llm.semantic.review"),
      owasp = if (is.null(item$owasp)) NA_character_ else tolower(as.character(item$owasp)),
      severity = severity,
      action = action,
      description = as.character(item$description %||% "Semantic reviewer finding."),
      match = NA_character_,
      start = NA_integer_,
      end = NA_integer_,
      source = "llm"
    )
  }
  out
}

.normalise_text <- function(text) {
  text <- stringi::stri_trans_nfkc(text)
  gsub("\\s+", " ", trimws(text), perl = TRUE)
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
  min(sum(scores), 1)
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
