#' Default Rule Bank
#'
#' @description
#' The built-in rule bank containing all default detection rules used by
#' `llmshieldr`. Each rule is a named list with a standardised structure that
#' the detectors iterate over.
#'
#' @details
#' ## Rule structure
#'
#' Every rule is a plain list with the following fields:
#'
#' | Field | Type | Description |
#' |---|---|---|
#' | `id` | character | Unique rule identifier |
#' | `type` | character | Category: `"secret"`, `"phi"`, `"injection"`, or `"output"` |
#' | `pattern` | character | Regex pattern used for detection |
#' | `severity` | numeric | Weighted severity score (0–100) |
#' | `action` | character | Default action: `"block"`, `"redact"`, `"warn"`, or `"allow"` |
#' | `mask` | character | Replacement text for redaction |
#' | `description` | character | Human-readable finding description |
#' | `owasp` | character | OWASP Top 10 for LLMs risk tag |
#' | `policy_tags` | character vector | Policies this rule applies to |
#'
#' ## OWASP LLM Risk Categories
#'
#' - **LLM01** — Prompt Injection
#' - **LLM02** — Sensitive Information Disclosure
#' - **LLM06** — Excessive Agency
#' - **LLM07** — System Prompt Leakage
#' - **LLM09** — Misinformation
#'
#' @format A list of named lists, each representing one detection rule.
#'
#' @examples
#' # Inspect the rule bank
#' length(rule_bank)
#'
#' # View the first rule
#' str(rule_bank[[1]])
#'
#' # List all rule IDs
#' vapply(rule_bank, `[[`, character(1), "id")
#'
#' # Filter rules by type
#' secret_rules <- Filter(function(r) r$type == "secret", rule_bank)
#' length(secret_rules)
#'
#' # Filter rules by OWASP tag
#' injection_rules <- Filter(function(r) r$owasp == "LLM01", rule_bank)
#' vapply(injection_rules, `[[`, character(1), "id")
#'
#' @export
rule_bank <- list(

# ── Secret detector rules ────────────────────────────────────────────────────

  list(
    id          = "secret_openai_key",
    type        = "secret",
    pattern     = "\\bsk-[a-zA-Z0-9]{20,}\\b",
    severity    = 100,
    action      = "block",
    mask        = "[REDACTED_API_KEY]",
    description = "OpenAI API key detected",
    owasp       = "LLM02",
    policy_tags = c("pharma_gxp", "enterprise_default", "finance_guard", "legal_guard")
  ),
  list(
    id          = "secret_aws_key",
    type        = "secret",
    pattern     = "\\bAKIA[A-Z0-9]{16}\\b",
    severity    = 100,
    action      = "block",
    mask        = "[REDACTED_AWS_KEY]",
    description = "AWS access key detected",
    owasp       = "LLM02",
    policy_tags = c("pharma_gxp", "enterprise_default", "finance_guard", "legal_guard")
  ),
  list(
    id          = "secret_bearer_token",
    type        = "secret",
    pattern     = "\\bBearer\\s+[A-Za-z0-9._~+/=-]{20,}\\b",
    severity    = 100,
    action      = "block",
    mask        = "[REDACTED_BEARER_TOKEN]",
    description = "Bearer token detected",
    owasp       = "LLM02",
    policy_tags = c("pharma_gxp", "enterprise_default", "finance_guard", "legal_guard")
  ),
  list(
    id          = "secret_generic_password",
    type        = "secret",
    pattern     = "(?i)(password|passwd|pwd)\\s*[=:]\\s*\\S+",
    severity    = 90,
    action      = "block",
    mask        = "[REDACTED_PASSWORD]",
    description = "Password or credential literal detected",
    owasp       = "LLM02",
    policy_tags = c("pharma_gxp", "enterprise_default", "finance_guard", "legal_guard")
  ),
  list(
    id          = "secret_connection_string",
    type        = "secret",
    pattern     = "(?i)(server|host)\\s*=\\s*[^;]+;.*(uid|user\\s*id|password)\\s*=",
    severity    = 95,
    action      = "block",
    mask        = "[REDACTED_CONNECTION_STRING]",
    description = "Database connection string detected",
    owasp       = "LLM02",
    policy_tags = c("pharma_gxp", "enterprise_default", "finance_guard", "legal_guard")
  ),
  list(
    id          = "secret_github_token",
    type        = "secret",
    pattern     = "\\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\\b",
    severity    = 100,
    action      = "block",
    mask        = "[REDACTED_GITHUB_TOKEN]",
    description = "GitHub personal access token detected",
    owasp       = "LLM02",
    policy_tags = c("pharma_gxp", "enterprise_default", "finance_guard", "legal_guard")
  ),
  list(
    id          = "secret_private_key",
    type        = "secret",
    pattern     = "-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
    severity    = 100,
    action      = "block",
    mask        = "[REDACTED_PRIVATE_KEY]",
    description = "Private key block detected",
    owasp       = "LLM02",
    policy_tags = c("pharma_gxp", "enterprise_default", "finance_guard", "legal_guard")
 ),

# ── PII/PHI detector rules ──────────────────────────────────────────────────

  list(
    id          = "phi_subject_id",
    type        = "phi",
    pattern     = "\\bUSUBJID\\b|\\bSUBJID\\b|\\bsubject[_\\s]?id\\b",
    severity    = 50,
    action      = "redact",
    mask        = "[REDACTED_SUBJECT_ID]",
    description = "CDISC USUBJID or subject identifier found in prompt",
    owasp       = "LLM02",
    policy_tags = c("pharma_gxp")
  ),
  list(
    id          = "phi_email",
    type        = "phi",
    pattern     = "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b",
    severity    = 30,
    action      = "redact",
    mask        = "[REDACTED_EMAIL]",
    description = "Email address detected",
    owasp       = "LLM02",
    policy_tags = c("pharma_gxp", "enterprise_default", "finance_guard", "legal_guard")
  ),
  list(
    id          = "phi_phone",
    type        = "phi",
    pattern     = "\\b\\d{3}[-.\\s]?\\d{3}[-.\\s]?\\d{4}\\b",
    severity    = 30,
    action      = "redact",
    mask        = "[REDACTED_PHONE]",
    description = "Phone number detected",
    owasp       = "LLM02",
    policy_tags = c("pharma_gxp", "enterprise_default", "finance_guard", "legal_guard")
  ),
  list(
    id          = "phi_ssn",
    type        = "phi",
    pattern     = "\\b\\d{3}-\\d{2}-\\d{4}\\b",
    severity    = 80,
    action      = "block",
    mask        = "[REDACTED_SSN]",
    description = "Social Security Number pattern detected",
    owasp       = "LLM02",
    policy_tags = c("pharma_gxp", "enterprise_default", "finance_guard", "legal_guard")
  ),
  list(
    id          = "phi_dob",
    type        = "phi",
    pattern     = "(?i)(date.of.birth|DOB|born.on)\\s*[:=]?\\s*\\d",
    severity    = 40,
    action      = "redact",
    mask        = "[REDACTED_DOB]",
    description = "Date of birth reference detected",
    owasp       = "LLM02",
    policy_tags = c("pharma_gxp", "enterprise_default")
  ),
  list(
    id          = "phi_mrn",
    type        = "phi",
    pattern     = "(?i)(MRN|medical.record)\\s*[:=#]?\\s*[A-Z0-9]+",
    severity    = 60,
    action      = "redact",
    mask        = "[REDACTED_MRN]",
    description = "Medical Record Number pattern detected",
    owasp       = "LLM02",
    policy_tags = c("pharma_gxp")
  ),
  list(
    id          = "phi_patient_narrative",
    type        = "phi",
    pattern     = "(?i)patient.{0,20}narrative|narrative.{0,20}patient|clinical.{0,20}narrative",
    severity    = 40,
    action      = "redact",
    mask        = "[REDACTED_PATIENT_NARRATIVE]",
    description = "Patient narrative block detected",
    owasp       = "LLM02",
    policy_tags = c("pharma_gxp")
  ),
  list(
    id          = "phi_credit_card",
    type        = "phi",
    pattern     = "\\b(?:\\d{4}[- ]?){3}\\d{4}\\b",
    severity    = 80,
    action      = "block",
    mask        = "[REDACTED_CREDIT_CARD]",
    description = "Credit card number pattern detected",
    owasp       = "LLM02",
    policy_tags = c("enterprise_default", "finance_guard")
  ),

# ── Prompt injection detector rules ──────────────────────────────────────────

  list(
    id          = "injection_ignore",
    type        = "injection",
    pattern     = "(?i)ignore\\s+(all\\s+)?previous\\s+instructions|override\\s+instructions|disregard\\s+(all\\s+)?(prior|previous|above)",
    severity    = 80,
    action      = "block",
    mask        = "[BLOCKED_INJECTION]",
    description = "Prompt injection: ignore/override instruction pattern",
    owasp       = "LLM01",
    policy_tags = c("pharma_gxp", "enterprise_default", "finance_guard", "legal_guard")
  ),
  list(
    id          = "injection_system_extract",
    type        = "injection",
    pattern     = "(?i)reveal\\s+(your\\s+)?system\\s+prompt|show\\s+(me\\s+)?(your\\s+)?instructions|what\\s+are\\s+your\\s+(system\\s+)?instructions|print\\s+your\\s+prompt|repeat\\s+(the|your)\\s+system\\s+prompt",
    severity    = 70,
    action      = "block",
    mask        = "[BLOCKED_SYSTEM_EXTRACT]",
    description = "System prompt extraction attempt",
    owasp       = "LLM07",
    policy_tags = c("pharma_gxp", "enterprise_default", "finance_guard", "legal_guard")
  ),
  list(
    id          = "injection_roleplay",
    type        = "injection",
    pattern     = "(?i)you\\s+are\\s+now\\s+|pretend\\s+(to\\s+be|you\\s+are)|act\\s+as\\s+(if|though)\\s+you|from\\s+now\\s+on\\s+you\\s+are",
    severity    = 60,
    action      = "warn",
    mask        = "[FLAGGED_ROLEPLAY]",
    description = "Jailbreak via forced role reassignment",
    owasp       = "LLM01",
    policy_tags = c("pharma_gxp", "enterprise_default", "finance_guard", "legal_guard")
  ),
  list(
    id          = "injection_encoding_bypass",
    type        = "injection",
    pattern     = "(?i)base64\\s+decode|rot13|hex\\s+decode|decode\\s+the\\s+following",
    severity    = 50,
    action      = "warn",
    mask        = "[FLAGGED_ENCODING_BYPASS]",
    description = "Encoding-based injection bypass attempt",
    owasp       = "LLM01",
    policy_tags = c("pharma_gxp", "enterprise_default")
  ),
  list(
    id          = "injection_dan",
    type        = "injection",
    pattern     = "(?i)\\bDAN\\b.*mode|\\bDAN\\b.*jailbreak|do\\s+anything\\s+now",
    severity    = 80,
    action      = "block",
    mask        = "[BLOCKED_JAILBREAK]",
    description = "DAN / do-anything-now jailbreak attempt",
    owasp       = "LLM01",
    policy_tags = c("pharma_gxp", "enterprise_default", "finance_guard", "legal_guard")
  ),

# ── Output scanner rules ────────────────────────────────────────────────────

  list(
    id          = "output_efficacy_claim",
    type        = "output",
    pattern     = "(?i)significantly\\s+reduced|proven\\s+safe|highly\\s+effective|superior\\s+to\\s+placebo|statistically\\s+significant\\s+improvement",
    severity    = 60,
    action      = "warn",
    mask        = "[FLAGGED_EFFICACY_CLAIM]",
    description = "Unsupported efficacy or safety claim in output",
    owasp       = "LLM09",
    policy_tags = c("pharma_gxp")
  ),
  list(
    id          = "output_diagnosis",
    type        = "output",
    pattern     = "(?i)you\\s+(have|are\\s+diagnosed\\s+with)|diagnosed\\s+with|treatment\\s+for|I\\s+recommend\\s+prescribing|you\\s+should\\s+take",
    severity    = 70,
    action      = "block",
    mask        = "[BLOCKED_DIAGNOSIS]",
    description = "Model attempting to diagnose, prescribe, or recommend treatment",
    owasp       = "LLM09",
    policy_tags = c("pharma_gxp")
  ),
  list(
    id          = "output_label_language",
    type        = "output",
    pattern     = "(?i)approved\\s+for\\s+(the\\s+)?treatment|indicated\\s+for|label\\s+claim|FDA[- ]approved\\s+for",
    severity    = 50,
    action      = "warn",
    mask        = "[FLAGGED_LABEL_LANGUAGE]",
    description = "Unreviewed regulatory label language detected in output",
    owasp       = "LLM09",
    policy_tags = c("pharma_gxp")
  ),
  list(
    id          = "output_autonomous_action",
    type        = "output",
    pattern     = "(?i)I\\s+will\\s+(now\\s+)?execute|running\\s+the\\s+following\\s+command|I\\s+have\\s+(deleted|modified|sent|submitted)",
    severity    = 60,
    action      = "warn",
    mask        = "[FLAGGED_AUTONOMOUS_ACTION]",
    description = "Model claiming autonomous action (excessive agency)",
    owasp       = "LLM06",
    policy_tags = c("pharma_gxp", "enterprise_default", "finance_guard", "legal_guard")
  ),
  list(
    id          = "output_financial_advice",
    type        = "output",
    pattern     = "(?i)you\\s+should\\s+(buy|sell|invest)|guaranteed\\s+return|risk[- ]free\\s+investment|financial\\s+advice",
    severity    = 60,
    action      = "warn",
    mask        = "[FLAGGED_FINANCIAL_ADVICE]",
    description = "Unsolicited financial advice or investment claim",
    owasp       = "LLM09",
    policy_tags = c("finance_guard")
  ),
  list(
    id          = "output_legal_opinion",
    type        = "output",
    pattern     = "(?i)this\\s+constitutes\\s+legal\\s+advice|as\\s+your\\s+(attorney|lawyer)|legally\\s+binding",
    severity    = 60,
    action      = "warn",
    mask        = "[FLAGGED_LEGAL_OPINION]",
    description = "Unauthorised legal opinion or advice in output",
    owasp       = "LLM09",
    policy_tags = c("legal_guard")
  )
)


# ── Internal: package environment for mutable rule bank ──────────────────────

.llmshieldr_env <- new.env(parent = emptyenv())
.llmshieldr_env$custom_rules <- list()


#' Get Active Rules
#'
#' Returns the full active rule set: default `rule_bank` plus any custom rules
#' added via [add_rule()].
#'
#' @return A list of rule objects.
#'
#' @examples
#' rules <- get_active_rules()
#' length(rules)
#'
#' @keywords internal
#' @noRd
get_active_rules <- function() {
  c(rule_bank, .llmshieldr_env$custom_rules)
}
