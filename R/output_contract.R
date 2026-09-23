#' Define a destination-specific output contract
#'
#' Contracts validate model output before an application treats it as JSON,
#' HTML, Markdown, or a file path. They do not execute SQL, shell commands, or
#' generated code. JSON Schema support is optional through `jsonvalidate`.
#'
#' @param format One of `"text"`, `"json"`, `"html"`, `"markdown"`, or
#'   `"path"`.
#' @param schema Optional JSON Schema object, JSON string, or schema file path.
#' @param validator Optional function receiving the output text and returning
#'   `TRUE`, `FALSE`, a message string, or a list with `valid` and `message`.
#' @param max_chars Optional maximum character count.
#' @param allowed_root Required root directory for `format = "path"`.
#' @param encode_html Whether HTML text is escaped before release.
#' @param on_invalid Action for invalid output: `"block"` or `"redact"`.
#' @param show_stats Show construction time and available usage metrics.
#'
#' @return A `shieldr_output_contract` object.
#' @examples
#' contract <- output_contract("json")
#' validate_output_contract('{"ok":true}', contract)
#' @export
output_contract <- function(format = c("text", "json", "html", "markdown", "path"),
                            schema = NULL,
                            validator = NULL,
                            max_chars = NULL,
                            allowed_root = NULL,
                            encode_html = TRUE,
                            on_invalid = c("block", "redact"),
                            show_stats = FALSE) {
  stats <- .stats_begin(show_stats, "output_contract")
  on.exit(.stats_end(stats), add = TRUE)
  format <- match.arg(format)
  if (!is.null(validator) && !is.function(validator)) {
    cli::cli_abort("{.arg validator} must be a function or {.code NULL}.")
  }
  .validate_nullable_limit(max_chars, "max_chars")
  if (!is.null(allowed_root)) .check_string(allowed_root, "allowed_root")
  if (identical(format, "path") && is.null(allowed_root)) {
    cli::cli_abort("{.arg allowed_root} is required for a path contract.")
  }
  if (!is.null(schema) && !identical(format, "json")) {
    cli::cli_abort("{.arg schema} is supported only for a JSON contract.")
  }
  .validate_flag(encode_html, "encode_html")
  on_invalid <- match.arg(on_invalid)
  structure(
    list(
      format = format,
      schema = schema,
      validator = validator,
      max_chars = max_chars,
      allowed_root = allowed_root,
      encode_html = encode_html,
      on_invalid = on_invalid
    ),
    class = "shieldr_output_contract"
  )
}

#' Validate output against a contract
#'
#' @param text Output text.
#' @param contract Contract from [output_contract()].
#' @param show_stats Show execution statistics as messages.
#'
#' @return A `shieldr_report`; `text_clean` contains the sink-safe rendering.
#' @examples
#' validate_output_contract("<b>Hello</b>", output_contract("html"))$text_clean
#' @export
validate_output_contract <- function(text, contract, show_stats = FALSE) {
  stats <- .stats_begin(show_stats, "validate_output_contract")
  on.exit(.stats_end(stats), add = TRUE)
  .stats_text_tokens(stats, text)
  .check_string(text, "text", allow_empty = TRUE)
  .validate_output_contract(contract)
  result <- .apply_output_contract(text, contract)
  findings <- result$findings
  risk <- .score_findings(findings)
  policy_obj <- shieldr_policy("output_contract", list(), list(redact_at = 0.3, block_at = 0.7))
  shieldr_report(
    action = .resolve_action(risk, findings, policy_obj),
    text_clean = result$text,
    findings = findings,
    risk_score = risk,
    policy = "output_contract",
    checks = "contract",
    metadata = .report_metadata(stage = "output_contract", format = contract$format)
  )
}

.validate_output_contract <- function(contract, allow_null = FALSE) {
  if (is.null(contract) && isTRUE(allow_null)) return(invisible(TRUE))
  if (!inherits(contract, "shieldr_output_contract")) {
    cli::cli_abort("{.arg contract} must be created by {.fn output_contract}.")
  }
  invisible(TRUE)
}

.apply_output_contract <- function(text, contract) {
  findings <- list()
  invalid <- function(id, message) {
    findings[[length(findings) + 1L]] <<- .synthetic_finding(
      id, "llm10", if (identical(contract$on_invalid, "block")) "critical" else "high",
      message, action = contract$on_invalid
    )
  }
  if (!is.null(contract$max_chars) && nchar(text) > contract$max_chars) {
    invalid("llm10.contract.length", "Output exceeds the contract character limit.")
  }
  if (identical(contract$format, "json")) {
    parsed <- tryCatch(jsonlite::fromJSON(text, simplifyVector = FALSE), error = identity)
    if (inherits(parsed, "error")) {
      invalid("llm10.contract.json", "Output is not valid JSON.")
    } else if (!is.null(contract$schema)) {
      if (!requireNamespace("jsonvalidate", quietly = TRUE)) {
        cli::cli_abort("Install the suggested {.pkg jsonvalidate} package to use JSON Schema contracts.")
      }
      schema <- if (is.list(contract$schema)) {
        jsonlite::toJSON(contract$schema, auto_unbox = TRUE, null = "null")
      } else {
        contract$schema
      }
      valid <- tryCatch(
        isTRUE(jsonvalidate::json_validate(text, schema, verbose = FALSE)),
        error = function(e) FALSE
      )
      if (!valid) invalid("llm10.contract.schema", "JSON output does not satisfy the configured schema.")
    }
  }
  if (identical(contract$format, "path") && !.path_within_root(text, contract$allowed_root)) {
    invalid("llm10.contract.path", "Output path escapes the configured root or is invalid.")
  }
  if (!is.null(contract$validator)) {
    validation <- tryCatch(contract$validator(text), error = identity)
    if (inherits(validation, "error")) {
      invalid("llm10.contract.validator_error", "The output contract validator failed.")
    } else {
      valid <- if (is.list(validation)) isTRUE(validation$valid) else isTRUE(validation)
      if (!valid) {
        message <- if (is.list(validation)) validation$message %||% "Custom output validation failed." else if (is.character(validation)) validation[[1L]] else "Custom output validation failed."
        invalid("llm10.contract.custom", as.character(message)[[1L]])
      }
    }
  }
  rendered <- if (identical(contract$format, "html") && isTRUE(contract$encode_html)) {
    .html_escape(text)
  } else {
    text
  }
  list(text = rendered, findings = findings)
}

.html_escape <- function(text) {
  text <- gsub("&", "&amp;", text, fixed = TRUE)
  text <- gsub("<", "&lt;", text, fixed = TRUE)
  text <- gsub(">", "&gt;", text, fixed = TRUE)
  text <- gsub('"', "&quot;", text, fixed = TRUE)
  gsub("'", "&#39;", text, fixed = TRUE)
}

.path_within_root <- function(path, root) {
  if (!is.character(path) || length(path) != 1L || is.na(path) || grepl("[\r\n]", path, perl = TRUE)) return(FALSE)
  root_abs <- normalizePath(root, winslash = "/", mustWork = FALSE)
  path_abs <- normalizePath(file.path(root_abs, path), winslash = "/", mustWork = FALSE)
  if (.Platform$OS.type == "windows") {
    root_abs <- tolower(root_abs)
    path_abs <- tolower(path_abs)
  }
  identical(path_abs, root_abs) || startsWith(path_abs, paste0(sub("/$", "", root_abs), "/"))
}
