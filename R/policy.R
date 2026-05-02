#' Build a guardrail policy
#'
#' `build_policy()` combines validated `shieldr_rule` objects with threshold
#' settings for the scanner layer. OWASP LLM Top 10 references are preserved on
#' each rule; see <https://genai.owasp.org/llm-top-10/>.
#'
#' @details
#' A policy is intentionally small and inspectable. It contains a policy name,
#' a list of deterministic rules, threshold values, and an optional rate guard.
#' The scanners do not mutate a policy; they read the rule list, create
#' findings, calculate a risk score from finding severities, and then compare
#' that score with the policy thresholds.
#'
#' Thresholds are merged over the package defaults:
#'
#' - `redact_at = 0.4`
#' - `block_at = 0.75`
#'
#' Lower thresholds make a policy stricter. Higher thresholds make accumulated
#' findings less likely to escalate. Critical findings and explicit `block`
#' rules still block regardless of threshold.
#'
#' @param name Policy name.
#' @param rules A list of `shieldr_rule` objects.
#' @param thresholds Threshold overrides. Missing values are filled from
#'   `redact_at = 0.4` and `block_at = 0.75`.
#' @param rate_guard Optional `shieldr_rate_guard`. When present, [secure_chat()]
#'   checks the guard before chat calls and updates it after successful calls.
#'
#' @return A `shieldr_policy`.
#' @examples
#' policy <- build_policy(rules = list(rule_pii_email()))
#' policy
#' @export
build_policy <- function(name = "custom",
                         rules = list(),
                         thresholds = list(),
                         rate_guard = NULL) {
  .check_string(name, "name")
  .check_rule_list(rules, "rules")
  defaults <- list(redact_at = 0.4, block_at = 0.75)
  thresholds <- utils::modifyList(defaults, thresholds, keep.null = TRUE)
  shieldr_policy(
    name = name,
    rules = rules,
    thresholds = thresholds,
    rate_guard = rate_guard
  )
}

.built_in_policy <- function(name, overrides = list()) {
  .check_string(name, "name")
  requested_name <- name
  policy_name <- if (identical(name, "baseline")) "enterprise_default" else name
  .check_choice(
    policy_name,
    "name",
    c(
      "enterprise_default",
      "pharma_gxp",
      "finance_strict",
      "education_safe",
      "open_research",
      "comprehensive",
      "custom"
    )
  )
  if (!is.list(overrides)) {
    cli::cli_abort("{.arg overrides} must be a list.")
  }

  enterprise_rules <- list(
    rule_injection_basic(),
    rule_injection_indirect(),
    rule_nlp_intent(),
    rule_pii_email(),
    rule_pii_phone(),
    rule_pii_ssn(),
    rule_phi_condition(),
    rule_secrets_api_key(),
    rule_secrets_bearer(),
    rule_secrets_aws(),
    rule_secrets_password(),
    .rule_secrets_connection_string(),
    rule_system_prompt_leak(),
    rule_agency_language()
  )

  rules <- switch(
    policy_name,
    enterprise_default = enterprise_rules,
    pharma_gxp = c(
      enterprise_rules,
      list(
        .rule_pii_mrn(),
        .rule_pii_usubjid(),
        rule_diagnosis_claim(),
        .rule_code_safety()
      )
    ),
    finance_strict = c(
      enterprise_rules,
      list(
        .rule_account_number(),
        rule_financial_advice(),
        .rule_investment_action()
      )
    ),
    education_safe = c(
      enterprise_rules,
      list(
        .rule_coppa_minor_pii(),
        .rule_academic_integrity()
      )
    ),
    open_research = list(
      rule_injection_basic(),
      rule_injection_indirect(),
      rule_nlp_intent(),
      rule_secrets_api_key(),
      rule_secrets_bearer(),
      rule_secrets_aws(),
      rule_secrets_password(),
      .rule_secrets_connection_string()
    ),
    comprehensive = c(
      enterprise_rules,
      list(
        .rule_pii_mrn(),
        .rule_pii_usubjid(),
        rule_diagnosis_claim(),
        .rule_code_safety(),
        .rule_account_number(),
        rule_financial_advice(),
        .rule_investment_action(),
        .rule_coppa_minor_pii(),
        .rule_academic_integrity()
      )
    ),
    custom = list()
  )

  thresholds <- switch(
    policy_name,
    pharma_gxp = list(redact_at = 0.3, block_at = 0.6),
    open_research = list(redact_at = 0.8, block_at = 0.95),
    comprehensive = list(redact_at = 0.4, block_at = 0.7),
    list()
  )

  guard <- if (policy_name %in% c("finance_strict", "comprehensive")) {
    rate_guard(max_tokens = 100000)
  } else {
    NULL
  }

  if (!is.null(overrides$rules)) {
    .check_rule_list(overrides$rules, "overrides$rules")
    rules <- c(rules, overrides$rules)
  }
  if (!is.null(overrides$thresholds)) {
    thresholds <- utils::modifyList(thresholds, overrides$thresholds, keep.null = TRUE)
  }
  if (!is.null(overrides$rate_guard)) {
    .check_rate_guard(overrides$rate_guard)
    guard <- overrides$rate_guard
  }

  policy <- build_policy(
    name = requested_name,
    rules = rules,
    thresholds = thresholds,
    rate_guard = guard
  )

  if (!is.null(overrides$trusted_sources)) {
    if (!is.character(overrides$trusted_sources)) {
      cli::cli_abort("{.arg overrides$trusted_sources} must be a character vector.")
    }
    policy$trusted_sources <- overrides$trusted_sources
  }

  policy
}

#' Load a built-in policy
#'
#' `policy()` is the easiest way to start. It returns a ready-to-use policy for
#' common safety profiles such as `"enterprise_default"`, `"pharma_gxp"`, and
#' `"comprehensive"`.
#'
#' @details
#' Built-in policies are assembled from the rule helpers in `R/rules.R`. They
#' use OWASP GenAI / LLM Top 10 categories as the organizing taxonomy, then add
#' common controls such as PII patterns, secret patterns, system-prompt
#' extraction checks, excessive-agency language, domain-specific claims, and
#' optional rate guards.
#'
#' Policy names:
#'
#' - `enterprise_default`: broad production baseline for injection, NLP intent,
#'   PII/PHI, secrets, system prompt extraction, and agency language.
#' - `pharma_gxp`: `enterprise_default` plus clinical identifiers, diagnosis
#'   and treatment language, unsafe code checks, and stricter thresholds.
#' - `finance_strict`: `enterprise_default` plus account numbers, investment
#'   advice language, autonomous trading language, and a token-rate guard.
#' - `education_safe`: `enterprise_default` plus minor-related PII and
#'   academic-integrity bypass language.
#' - `open_research`: a smaller open-workflow profile focused on injection and
#'   secrets, with higher thresholds.
#' - `comprehensive`: a maximum-coverage profile combining the enterprise,
#'   pharma, finance, education, code-safety, and rate-guard controls. Uses
#'   moderate thresholds (`redact_at = 0.4`, `block_at = 0.7`). For pharma-tier
#'   strictness, supply `overrides = list(thresholds = list(redact_at = 0.3,
#'   block_at = 0.6))` explicitly.
#' - `custom`: no rules, default thresholds.
#' - `baseline`: backward-compatible alias for `enterprise_default`.
#'
#' These policies are starting points. They are transparent, testable, and can
#' be extended with [add_rule()] for application-specific requirements.
#'
#' @param name Built-in policy name. Defaults to `"enterprise_default"`.
#' @param overrides Optional list with `rules`, `thresholds`, `rate_guard`, or
#'   `trusted_sources` entries.
#'
#' @return A `shieldr_policy`.
#' @examples
#' policy()
#' policy("open_research", overrides = list(thresholds = list(redact_at = 0.7)))
#' @export
policy <- function(name = "enterprise_default", overrides = list()) {
  .built_in_policy(name, overrides)
}

.built_in_policy_info <- function() {
  data.frame(
    name = c(
      "enterprise_default",
      "baseline",
      "pharma_gxp",
      "finance_strict",
      "education_safe",
      "open_research",
      "comprehensive",
      "custom"
    ),
    description = c(
      "Production baseline for prompt injection, NLP intent, PII/PHI, secrets, system-prompt extraction, and agency language.",
      "Backward-compatible alias for enterprise_default.",
      "Clinical and regulated-workflow controls on top of enterprise_default.",
      "Financial-services controls with account, advice, trading, and rate-guard checks.",
      "Education controls for minor PII and academic-integrity bypasses.",
      "Lighter research profile focused on injection and secrets with higher thresholds.",
      "Maximum built-in coverage across enterprise, clinical, finance, education, code, and rate limits. Uses moderate thresholds (redact_at = 0.4, block_at = 0.7). For pharma-tier strictness, supply overrides = list(thresholds = list(redact_at = 0.3, block_at = 0.6)) explicitly.",
      "Empty policy for fully custom rule sets."
    ),
    stringsAsFactors = FALSE
  )
}

#' List available built-in policies
#'
#' Returns the built-in policy names and their high-level behavior. Use these
#' names directly in scanners and orchestration helpers, for example
#' `scan_prompt("text", policy = "comprehensive")`.
#'
#' @param selected Optional policy name or `shieldr_policy` to mark in the
#'   returned table.
#'
#' @return A data frame with policy names, descriptions, rule counts,
#' thresholds, rate-guard availability, and a `selected` column when requested.
#' @examples
#' available_policies()
#' available_policies("comprehensive")
#' scan_prompt("hello", policy = "enterprise_default")
#' @export
available_policies <- function(selected = NULL) {
  info <- .built_in_policy_info()
  policies <- lapply(info$name, .built_in_policy)
  info$rules <- vapply(policies, function(policy) length(policy$rules), integer(1))
  info$redact_at <- vapply(policies, function(policy) policy$thresholds$redact_at, numeric(1))
  info$block_at <- vapply(policies, function(policy) policy$thresholds$block_at, numeric(1))
  info$rate_guard <- vapply(policies, function(policy) !is.null(policy$rate_guard), logical(1))
  if (!is.null(selected)) {
    selected_name <- .selected_policy_name(selected)
    info$selected <- info$name == selected_name
    if (identical(selected_name, "enterprise_default")) {
      info$selected <- info$selected | info$name == "baseline"
    }
  }
  info
}

.selected_policy_name <- function(selected) {
  if (inherits(selected, "shieldr_policy")) {
    return(if (identical(selected$name, "baseline")) "enterprise_default" else selected$name)
  }
  .check_string(selected, "selected")
  if (identical(selected, "baseline")) {
    return("enterprise_default")
  }
  .check_choice(
    selected,
    "selected",
    c(
      "enterprise_default",
      "pharma_gxp",
      "finance_strict",
      "education_safe",
      "open_research",
      "comprehensive",
      "custom"
    )
  )
  selected
}

.as_policy <- function(policy) {
  if (inherits(policy, "shieldr_policy")) {
    return(policy)
  }
  if (is.character(policy) && length(policy) == 1L && !is.na(policy)) {
    return(.built_in_policy(policy))
  }
  .check_policy(policy)
  policy
}

#' Add a rule to a policy
#'
#' `add_rule()` appends one validated rule to an existing policy. The function
#' returns the modified policy invisibly so it can be used in assignment or
#' pipes.
#'
#' @details
#' A rule can be regex-based or function-based, but not both. Regex rules are
#' best when you need span-level redaction. Function rules are useful when the
#' condition is easier to express in R, such as "this text contains both a
#' student reference and a home-address phrase".
#'
#' Severity determines the numeric contribution to the report score:
#'
#' - `low`: `0.1`
#' - `medium`: `0.3`
#' - `high`: `0.6`
#' - `critical`: `1.0`
#'
#' The rule `action` is the rule author's preferred outcome when the rule
#' fires. The final report action also considers total score and policy
#' thresholds.
#'
#' @param policy A `shieldr_policy` or built-in policy name such as `"comprehensive"`.
#' @param id Rule identifier.
#' @param pattern Regular expression pattern, or `NULL`.
#' @param fn Predicate function, or `NULL`.
#' @param owasp Optional OWASP category.
#' @param severity One of `"low"`, `"medium"`, `"high"`, or `"critical"`.
#' @param action One of `"allow"`, `"redact"`, or `"block"`.
#' @param description Rule description.
#'
#' @return The modified `shieldr_policy`, invisibly.
#' @examples
#' policy <- build_policy()
#' policy <- add_rule(policy, "demo.secret", pattern = "SECRET", owasp = "llm02")
#' @export
add_rule <- function(policy,
                     id,
                     pattern = NULL,
                     fn = NULL,
                     owasp = NULL,
                     severity = "medium",
                     action = "redact",
                     description = "") {
  policy <- .as_policy(policy)
  .check_string(id, "id")
  ids <- vapply(policy$rules, `[[`, character(1), "id")
  if (id %in% ids) {
    cli::cli_abort("A rule with id {.val {id}} already exists in this policy.")
  }
  policy$rules <- c(
    policy$rules,
    list(
      shieldr_rule(
        id = id,
        pattern = pattern,
        fn = fn,
        owasp = owasp,
        severity = severity,
        action = action,
        description = description
      )
    )
  )
  invisible(policy)
}

#' Remove a rule from a policy
#'
#' @param policy A `shieldr_policy` or built-in policy name such as `"comprehensive"`.
#' @param id Rule identifier to remove.
#'
#' @return The modified `shieldr_policy`, invisibly.
#' @examples
#' policy <- build_policy(rules = list(rule_pii_email()))
#' policy <- remove_rule(policy, "llm02.pii.email")
#' @export
remove_rule <- function(policy, id) {
  policy <- .as_policy(policy)
  .check_string(id, "id")
  ids <- vapply(policy$rules, `[[`, character(1), "id")
  keep <- ids != id
  if (all(keep)) {
    cli::cli_warn("Rule {.val {id}} was not found.")
  }
  policy$rules <- policy$rules[keep]
  invisible(policy)
}

#' List policy rules
#'
#' `list_rules()` returns a compact inventory of a policy's rule set. It is
#' intended for audits, examples, tests, and pre-deployment reviews.
#'
#' @details
#' The `has_pattern` and `has_fn` columns identify whether each rule is regex
#' based or function based. Regex rules can produce redaction spans directly.
#' Function rules may produce findings without spans unless the function
#' returns span metadata.
#'
#' @param policy A `shieldr_policy` or built-in policy name such as `"comprehensive"`.
#'
#' @return A data frame with columns `id`, `owasp`, `severity`, `action`,
#'   `has_pattern`, and `has_fn`.
#' @examples
#' list_rules(policy("custom"))
#' @export
list_rules <- function(policy) {
  policy <- .as_policy(policy)
  out <- data.frame(
    id = vapply(policy$rules, `[[`, character(1), "id"),
    owasp = vapply(policy$rules, function(rule) rule$owasp %||% NA_character_, character(1)),
    severity = vapply(policy$rules, `[[`, character(1), "severity"),
    action = vapply(policy$rules, `[[`, character(1), "action"),
    has_pattern = vapply(policy$rules, function(rule) !is.null(rule$pattern), logical(1)),
    has_fn = vapply(policy$rules, function(rule) !is.null(rule$fn), logical(1)),
    stringsAsFactors = FALSE
  )
  cli::cli_text("{.strong {policy$name}}: {nrow(out)} rule{?s}")
  if (nrow(out) > 0L) {
    print(out, row.names = FALSE)
  }
  out
}

`%||%` <- function(x, y) {
  if (is.null(x)) y else x
}
