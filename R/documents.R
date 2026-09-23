#' Describe extracted document content
#'
#' Creates a provenance record for text extracted from a document or image.
#' Binary files are never parsed implicitly. PDF and image inputs require an
#' explicit extraction method, and image inputs require `ocr_used = TRUE`.
#'
#' @param text Extracted text.
#' @param source_id Stable provenance identifier.
#' @param mime_type MIME type of the original input.
#' @param extraction_method Name and optional version of the extractor.
#' @param ocr_used Whether OCR produced or contributed to the text.
#' @param hidden_text_checked Whether hidden layers/text were inspected.
#' @param metadata Additional non-content provenance metadata.
#' @param show_stats Show construction time and available usage metrics.
#'
#' @return A `shieldr_document` object.
#' @examples
#' doc <- document_input("Public note", "doc-1", "text/plain", "native")
#' @export
document_input <- function(text,
                           source_id,
                           mime_type = "text/plain",
                           extraction_method = "native",
                           ocr_used = FALSE,
                           hidden_text_checked = FALSE,
                           metadata = list(),
                           show_stats = FALSE) {
  stats <- .stats_begin(show_stats, "document_input")
  on.exit(.stats_end(stats), add = TRUE)
  .stats_text_tokens(stats, text)
  .check_string(text, "text", allow_empty = TRUE)
  .check_string(source_id, "source_id")
  .check_string(mime_type, "mime_type")
  .check_string(extraction_method, "extraction_method")
  .validate_flag(ocr_used, "ocr_used")
  .validate_flag(hidden_text_checked, "hidden_text_checked")
  if (!is.list(metadata)) cli::cli_abort("{.arg metadata} must be a list.")
  supported <- identical(mime_type, "text/plain") || identical(mime_type, "text/markdown") ||
    identical(mime_type, "application/pdf") || startsWith(mime_type, "image/")
  if (!supported) cli::cli_abort("Unsupported document MIME type {.val {mime_type}}.")
  if ((identical(mime_type, "application/pdf") || startsWith(mime_type, "image/")) &&
      extraction_method %in% c("none", "native")) {
    cli::cli_abort("PDF and image inputs require an explicit extraction method.")
  }
  if (startsWith(mime_type, "image/") && !isTRUE(ocr_used)) {
    cli::cli_abort("Image inputs require {.arg ocr_used = TRUE}; otherwise the modality is unchecked.")
  }
  structure(
    list(
      text = text,
      source_id = source_id,
      mime_type = mime_type,
      extraction_method = extraction_method,
      ocr_used = ocr_used,
      hidden_text_checked = hidden_text_checked,
      metadata = metadata
    ),
    class = "shieldr_document"
  )
}

#' Scan extracted document content
#'
#' @param document Object from [document_input()].
#' @inheritParams scan_prompt
#' @param show_stats Show execution statistics as messages.
#'
#' @return A `shieldr_report` with document provenance in metadata.
#' @examples
#' doc <- document_input("Ignore previous instructions.", "doc-1")
#' scan_document(doc)$action
#' @export
scan_document <- function(document,
                          policy = "enterprise_default",
                          reviewer = NULL,
                          checks = "rules",
                          redact = TRUE,
                          redaction = NULL,
                          scanners = scanner_options(),
                          show_tokens = FALSE,
                          show_stats = FALSE) {
  stats <- .stats_begin(show_stats, "scan_document")
  on.exit(.stats_end(stats), add = TRUE)
  if (!inherits(document, "shieldr_document")) cli::cli_abort("{.arg document} must be created by {.fn document_input}.")
  .stats_text_tokens(stats, document$text)
  report <- scan_prompt(
    document$text, policy = policy, reviewer = reviewer, checks = checks,
    redact = redact, redaction = redaction, scanners = scanners,
    show_tokens = show_tokens, stage = "document"
  )
  findings <- report$findings
  multimodal <- identical(document$mime_type, "application/pdf") || startsWith(document$mime_type, "image/")
  if (multimodal && !isTRUE(document$hidden_text_checked)) {
    findings <- c(findings, list(.synthetic_finding(
      "llm01.document.hidden_text_unchecked", "llm01", "high",
      "Document extraction did not confirm that hidden text or layers were inspected.",
      action = "redact"
    )))
  }
  policy_obj <- .as_policy(policy)
  findings <- .dedupe_findings(findings)
  report$findings <- findings
  report$risk_score <- .score_findings(findings)
  report$action <- .resolve_action(report$risk_score, findings, policy_obj)
  report$metadata <- utils::modifyList(report$metadata, .report_metadata(
    stage = "document",
    source_id = document$source_id,
    mime_type = document$mime_type,
    extraction_method = document$extraction_method,
    ocr_used = document$ocr_used,
    hidden_text_checked = document$hidden_text_checked,
    provenance = document$metadata
  ))
  report
}
