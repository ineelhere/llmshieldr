#' llmshieldr: Safety Guardrails for LLM Workflows in R
#'
#' A model-agnostic safety layer for R developers building with large
#' language models. The package covers the OWASP LLM Top 10 (2025) risk
#' categories through composable policies, deterministic rules, optional
#' semantic review, lightweight NLP intent checks, local Ollama helpers, output
#' scanning, rate guards, and audit logs.
#'
#' @importFrom cli cli_abort cli_bullets cli_h1 cli_text cli_warn col_cyan col_green col_grey col_red col_yellow
#' @importFrom digest digest
#' @importFrom jsonlite fromJSON toJSON
#' @importFrom rlang check_installed
#' @importFrom stringi stri_trans_nfkc
#' @keywords internal
"_PACKAGE"
