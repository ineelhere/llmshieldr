#' llmshieldr: Safety Guardrails for Large Language Model Workflows
#'
#' Inspectable, model-agnostic guardrails for large language model applications
#' in R. The package scans prompts, conversations, retrieved context, documents,
#' tool calls and outputs, streams, URLs, and model responses. Composable
#' policies combine deterministic rules, optional detectors and semantic
#' review, rate limits, output contracts, grounding checks, and privacy-aware
#' audits. [secure_chat()] applies these checks around provider-neutral chat
#' workflows; the individual `scan_*()` functions guard application-owned
#' boundaries.
#'
#' @importFrom cli cli_abort cli_bullets cli_warn col_cyan col_green col_grey col_red col_yellow
#' @importFrom digest digest
#' @importFrom jsonlite fromJSON toJSON
#' @importFrom rlang check_installed
#' @importFrom stringi stri_trans_nfkc stri_replace_all_regex
#' @keywords internal
"_PACKAGE"
