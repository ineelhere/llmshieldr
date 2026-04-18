#' Rule object format and default rule bank
#'
#' This file defines the structure of rule objects and provides the default rule bank.
#'
#' @details
#' Each rule is a list with the following fields:
#' - id: unique identifier
#' - type: category (e.g., "secret", "phi", "injection")
#' - pattern: regex pattern
#' - severity: numeric score
#' - action: default action ("block", "redact", "warn", "allow")
#' - mask: replacement text for redaction
#' - description: human-readable description
#' - owasp: OWASP LLM risk tag
#' - policy_tags: vector of policy names this rule applies to
#'
#' @export
rule_bank <- list(
  # Secret detector rules
  list(
    id = "api_key_openai",
    type = "secret",
    pattern = "\\bsk-[a-zA-Z0-9]{48}\\b",
    severity = 100,
    action = "block",
    mask = "[REDACTED_API_KEY]",
    description = "OpenAI API key detected",
    owasp = "LLM02",
    policy_tags = c("pharma_gxp", "enterprise_default")
  ),
  list(
    id = "bearer_token",
    type = "secret",
    pattern = "\\bBearer [a-zA-Z0-9]{20,}\\b",
    severity = 100,
    action = "block",
    mask = "[REDACTED_BEARER_TOKEN]",
    description = "Bearer token detected",
    owasp = "LLM02",
    policy_tags = c("pharma_gxp", "enterprise_default")
  ),
  # PHI/PII rules
  list(
    id = "phi_subject_id",
    type = "phi",
    pattern = "\\bUSUBJID\\b|\\bSUBJID\\b|subject[_\\s]?id",
    severity = 50,
    action = "redact",
    mask = "[REDACTED_SUBJECT_ID]",
    description = "CDISC USUBJID or subject identifier found",
    owasp = "LLM02",
    policy_tags = c("pharma_gxp")
  ),
  list(
    id = "email",
    type = "phi",
    pattern = "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b",
    severity = 30,
    action = "redact",
    mask = "[REDACTED_EMAIL]",
    description = "Email address detected",
    owasp = "LLM02",
    policy_tags = c("pharma_gxp", "enterprise_default")
  ),
  list(
    id = "phone_number",
    type = "phi",
    pattern = "\\b\\d{3}[-.]?\\d{3}[-.]?\\d{4}\\b",
    severity = 30,
    action = "redact",
    mask = "[REDACTED_PHONE]",
    description = "Phone number detected",
    owasp = "LLM02",
    policy_tags = c("pharma_gxp", "enterprise_default")
  ),
  # Injection rules
  list(
    id = "ignore_instructions",
    type = "injection",
    pattern = "ignore previous instructions|ignore all previous|override instructions",
    severity = 80,
    action = "block",
    mask = "[REDACTED_INJECTION]",
    description = "Prompt injection attempt: ignore instructions",
    owasp = "LLM01",
    policy_tags = c("pharma_gxp", "enterprise_default")
  ),
  list(
    id = "system_prompt_leak",
    type = "injection",
    pattern = "system prompt|reveal system|show instructions",
    severity = 80,
    action = "block",
    mask = "[REDACTED_INJECTION]",
    description = "Attempt to extract system prompt",
    owasp = "LLM01",
    policy_tags = c("pharma_gxp", "enterprise_default")
  )
)