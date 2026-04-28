#' Build a guardrail policy
#'
#' `build_policy()` combines validated `shieldr_rule` objects with threshold
#' settings for the scanner layer. OWASP LLM Top 10 references are preserved on
#' each rule; see <https://genai.owasp.org/llm-top-10/>.
#'
#' @param name Policy name.
#' @param rules A list of `shieldr_rule` objects.
#' @param thresholds Threshold overrides. Missing values are filled from
#'   `redact_at = 0.4` and `block_at = 0.75`.
#' @param rate_guard Optional `shieldr_rate_guard`.
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

#' Load a policy preset
#'
#' Creates a hard-coded policy preset covering common industry profiles and
#' OWASP LLM Top 10 categories.
#'
#' @param name One of `"enterprise_default"`, `"pharma_gxp"`,
#'   `"finance_strict"`, `"education_safe"`, `"open_research"`, `"custom"`,
#'   or `"baseline"`. `"baseline"` is a backward-compatible alias for
#'   `"enterprise_default"`.
#' @param overrides Optional list with `rules`, `thresholds`, `rate_guard`, or
#'   `trusted_sources` entries.
#'
#' @return A `shieldr_policy`.
#' @examples
#' policy_preset("enterprise_default")
#' policy_preset("open_research", overrides = list(thresholds = list(redact_at = 0.7)))
#' @export
policy_preset <- function(name, overrides = list()) {
  .check_string(name, "name")
  requested_name <- name
  preset_name <- if (identical(name, "baseline")) "enterprise_default" else name
  .check_choice(
    preset_name,
    "name",
    c(
      "enterprise_default",
      "pharma_gxp",
      "finance_strict",
      "education_safe",
      "open_research",
      "custom"
    )
  )
  if (!is.list(overrides)) {
    cli::cli_abort("{.arg overrides} must be a list.")
  }

  enterprise_rules <- list(
    rule_injection_basic(),
    rule_injection_indirect(),
    rule_pii_email(),
    rule_pii_phone(),
    rule_pii_ssn(),
    rule_secrets_api_key(),
    rule_secrets_bearer(),
    rule_secrets_aws(),
    .rule_secrets_connection_string(),
    rule_system_prompt_leak(),
    rule_agency_language()
  )

  rules <- switch(
    preset_name,
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
        shieldr_rule(
          id = "llm06.investment_advice.action",
          pattern = "(?i)\\bI\\s+will\\s+(buy|sell|trade|invest)\\b|\\bplacing\\s+the\\s+order\\b",
          owasp = "llm06",
          severity = "critical",
          action = "block",
          description = "Autonomous investment-action language."
        )
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
      rule_secrets_api_key(),
      rule_secrets_bearer(),
      rule_secrets_aws(),
      .rule_secrets_connection_string()
    ),
    custom = list()
  )

  thresholds <- switch(
    preset_name,
    pharma_gxp = list(redact_at = 0.3, block_at = 0.6),
    open_research = list(redact_at = 0.8, block_at = 0.95),
    list()
  )

  guard <- if (identical(preset_name, "finance_strict")) {
    rate_guard(max_tokens = 100000, cost_limit_usd = 5.00)
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

#' Add a rule to a policy
#'
#' @param policy A `shieldr_policy`.
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
  .check_policy(policy)
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
#' @param policy A `shieldr_policy`.
#' @param id Rule identifier to remove.
#'
#' @return The modified `shieldr_policy`, invisibly.
#' @examples
#' policy <- build_policy(rules = list(rule_pii_email()))
#' policy <- remove_rule(policy, "llm02.pii.email")
#' @export
remove_rule <- function(policy, id) {
  .check_policy(policy)
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
#' @param policy A `shieldr_policy`.
#'
#' @return A data frame with columns `id`, `owasp`, `severity`, `action`,
#'   `has_pattern`, and `has_fn`.
#' @examples
#' list_rules(policy_preset("custom"))
#' @export
list_rules <- function(policy) {
  .check_policy(policy)
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
