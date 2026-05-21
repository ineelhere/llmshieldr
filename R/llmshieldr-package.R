#' llmshieldr: Safety Guardrails for Large Language Model Workflows
#'
#' A model-agnostic safety layer for 'R' developers building with large language
#' model applications. The package maps starter controls to the Open
#' Worldwide Application Security Project Top 10 for Large Language
#' Model Applications 2025 risk categories through composable policies,
#' deterministic rules, optional semantic review, lightweight natural language
#' processing intent checks, conversation, tool-call, streaming-output,
#' retrieval-augmented generation context, and output scanning,
#' workflows with the 'Ollama' local web service, rate guards, and audit logs.
#'
#' @importFrom cli cli_abort cli_bullets cli_warn col_cyan col_green col_grey col_red col_yellow
#' @importFrom digest digest
#' @importFrom jsonlite fromJSON toJSON
#' @importFrom rlang check_installed
#' @importFrom stringi stri_trans_nfkc stri_replace_all_regex
#' @keywords internal
"_PACKAGE"
