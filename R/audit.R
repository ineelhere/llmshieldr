#' Create a Shield Audit Object
#'
#' Constructs a `shield_audit` S3 object that captures the full lifecycle
#' record of one shielded LLM interaction. Used internally by
#' [secure_chat()] and can also be constructed manually for custom
#' integrations.
#'
#' @param timestamp A `POSIXct` timestamp. Defaults to [Sys.time()].
#' @param policy Character. The policy name that was applied.
#' @param model Character. The LLM model identifier.
#' @param provider Character. The provider class name.
#' @param input_report A `scan_report` from [scan_prompt()].
#' @param output_report A `scan_report` from [scan_output()].
#' @param final_action Character. The action that was taken.
#' @param redactions A list of redaction log entries.
#' @param ... Additional named fields to include in the audit record.
#'
#' @return A `shield_audit` S3 object.
#'
#' @seealso [write_audit_log()], [secure_chat()]
#'
#' @examples
#' # Create a manual audit record
#' input_report <- scan_prompt("Safe SDTM question.")
#' output_report <- scan_output("The AE domain stores adverse events.")
#'
#' audit <- shield_audit(
#'   policy       = "pharma_gxp",
#'   model        = "gemma3:4b",
#'   provider     = "ollama",
#'   input_report = input_report,
#'   output_report = output_report,
#'   final_action = "allow",
#'   redactions   = list()
#' )
#' audit
#'
#' @export
shield_audit <- function(timestamp     = Sys.time(),
                         policy        = "default",
                         model         = "unknown",
                         provider      = "unknown",
                         input_report  = NULL,
                         output_report = NULL,
                         final_action  = "allow",
                         redactions    = list(),
                         ...) {
  structure(
    list(
      timestamp     = timestamp,
      policy        = policy,
      model         = model,
      provider      = provider,
      input_report  = input_report,
      output_report = output_report,
      final_action  = final_action,
      redactions    = redactions,
      ...
    ),
    class = "shield_audit"
  )
}


#' Write Audit Log to JSONL File
#'
#' Appends a `shield_audit` record as a single JSON line to a JSONL
#' (JSON Lines) file. Each call appends one line, making the file
#' suitable for streaming audit ingestion and SIEM integration.
#'
#' @param audit A `shield_audit` object (from [shield_audit()] or
#'   [secure_chat()]).
#' @param path Character. File path for JSONL output. The file is created
#'   if it does not exist; otherwise, the record is appended.
#'
#' @return Invisibly returns `path`.
#'
#' @seealso [shield_audit()], [secure_chat()]
#'
#' @examples
#' # Create and write an audit record
#' input_report <- scan_prompt("Safe SDTM question.")
#' output_report <- scan_output("The AE domain stores adverse events.")
#'
#' audit <- shield_audit(
#'   policy       = "pharma_gxp",
#'   model        = "gemma3:4b",
#'   provider     = "ollama",
#'   input_report = input_report,
#'   output_report = output_report,
#'   final_action = "allow"
#' )
#'
#' # Write to a temporary JSONL file
#' tmp <- tempfile(fileext = ".jsonl")
#' write_audit_log(audit, tmp)
#' readLines(tmp)
#'
#' # Append a second record
#' write_audit_log(audit, tmp)
#' length(readLines(tmp))  # 2 lines
#'
#' @export
write_audit_log <- function(audit, path) {
  if (!inherits(audit, "shield_audit")) {
    abort_input_validation(
      arg      = "audit",
      expected = "a {.cls shield_audit} object",
      got      = paste0("{.obj_type_friendly {audit}}"),
      fn       = "write_audit_log"
    )
  }
  if (!rlang::is_string(path)) {
    abort_input_validation(
      arg      = "path",
      expected = "a single file path string",
      got      = paste0("{.obj_type_friendly {path}}"),
      fn       = "write_audit_log"
    )
  }

  # Convert to a flat JSON-serialisable list
  audit_flat <- list(
    timestamp     = format(audit$timestamp, "%Y-%m-%dT%H:%M:%S%z"),
    policy        = audit$policy,
    model         = audit$model,
    provider      = audit$provider,
    reviewer_model = audit$reviewer_model %||% NA_character_,
    reviewer_provider = audit$reviewer_provider %||% NA_character_,
    checks        = audit$checks %||% NA_character_,
    input_score   = audit$input_report$score %||% NA_real_,
    input_band    = audit$input_report$band %||% NA_character_,
    input_passed  = audit$input_report$passed %||% NA,
    output_score  = audit$output_report$score %||% NA_real_,
    output_band   = audit$output_report$band %||% NA_character_,
    output_passed = audit$output_report$passed %||% NA,
    final_action  = audit$final_action,
    rules_triggered = vapply(
      c(audit$input_report$findings, audit$output_report$findings),
      `[[`, character(1), "id"
    ),
    redaction_count = length(audit$redactions)
  )

  json_line <- jsonlite::toJSON(audit_flat, auto_unbox = TRUE)
  write(json_line, file = path, append = TRUE)

  invisible(path)
}
