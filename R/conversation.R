#' Scan a conversation while preserving message roles
#'
#' `scan_conversation()` scans multi-message chat histories instead of a single
#' string. Each message is scanned with the role-appropriate surface and the
#' returned reports preserve message index and role in `metadata`.
#'
#' @details
#' Role handling:
#'
#' - `assistant` and `model` messages are scanned with [scan_output()].
#' - `tool` and `function` messages are scanned with [scan_tool_output()].
#' - all other roles, including `system`, `developer`, and `user`, are scanned
#'   with [scan_prompt()].
#'
#' This function does not assemble or call a model. It is intended for
#' preflight checks, audits, and regression tests over stored chat histories.
#'
#' @param messages A data frame with role and content columns, a list of message
#'   objects with `role` and `content` fields, or a character vector of user
#'   messages.
#' @param role_col Role column name for data-frame inputs.
#' @param content_col Content column name for data-frame inputs. If `NULL`, a
#'   likely column such as `content`, `text`, or `message` is inferred.
#' @param policy A `shieldr_policy` or built-in policy name.
#' @param reviewer Optional reviewer function or object with `$chat()`.
#' @param checks One of `"rules"`, `"nlp"`, `"llm"`, or `"both"`.
#' @param redaction Optional redaction strategy from [redaction_strategy()].
#' @param scanners Optional scanner configuration from [scanner_options()].
#' @param show_tokens Whether to attach token counts when `ellmer` is available.
#'
#' @return A list of `shieldr_report` objects, one per message.
#' @examples
#' history <- data.frame(
#'   role = c("user", "assistant"),
#'   content = c("Summarize this.", "I will now delete the records."),
#'   stringsAsFactors = FALSE
#' )
#'
#' scan_conversation(history)
#' @export
scan_conversation <- function(messages,
                              role_col = "role",
                              content_col = NULL,
                              policy = "enterprise_default",
                              reviewer = NULL,
                              checks = "rules",
                              redaction = NULL,
                              scanners = scanner_options(),
                              show_tokens = FALSE) {
  data <- .conversation_to_data_frame(messages)
  .check_string(role_col, "role_col")
  if (!role_col %in% names(data)) {
    cli::cli_abort("{.arg role_col} must name a column in {.arg messages}.")
  }
  content_name <- if (is.null(content_col)) {
    .infer_conversation_content_col(data)
  } else {
    .check_string(content_col, "content_col")
    content_col
  }
  if (!content_name %in% names(data)) {
    cli::cli_abort("{.arg content_col} must name a column in {.arg messages}.")
  }

  roles <- tolower(as.character(data[[role_col]]))
  roles[is.na(roles) | !nzchar(roles)] <- "user"
  content <- as.character(data[[content_name]])
  content[is.na(content)] <- ""

  reports <- vector("list", length(content))
  for (i in seq_along(content)) {
    role <- roles[[i]]
    report <- if (role %in% c("assistant", "model")) {
      scan_output(
        content[[i]],
        policy = policy,
        reviewer = reviewer,
        checks = checks,
        redaction = redaction,
        scanners = scanners,
        show_tokens = show_tokens
      )
    } else if (role %in% c("tool", "function")) {
      scan_tool_output(
        role,
        content[[i]],
        policy = policy,
        reviewer = reviewer,
        checks = checks,
        redaction = redaction,
        scanners = scanners,
        show_tokens = show_tokens
      )
    } else {
      scan_prompt(
        content[[i]],
        policy = policy,
        reviewer = reviewer,
        checks = checks,
        redaction = redaction,
        scanners = scanners,
        show_tokens = show_tokens
      )
    }

    report$metadata <- utils::modifyList(
      report$metadata %||% list(),
      .report_metadata(
        stage = "conversation",
        message_index = i,
        role = role,
        role_col = role_col,
        content_col = content_name
      )
    )
    reports[[i]] <- report
  }

  reports
}

.conversation_to_data_frame <- function(messages) {
  if (is.data.frame(messages)) {
    return(messages)
  }
  if (is.character(messages)) {
    return(data.frame(
      role = rep("user", length(messages)),
      content = messages,
      stringsAsFactors = FALSE
    ))
  }
  if (is.list(messages)) {
    if (length(messages) == 0L) {
      return(data.frame(role = character(), content = character(), stringsAsFactors = FALSE))
    }
    if (!is.null(messages$role) || !is.null(messages$content) || !is.null(messages$text)) {
      return(data.frame(
        role = as.character(messages$role %||% "user"),
        content = as.character(messages$content %||% messages$text %||% ""),
        stringsAsFactors = FALSE
      ))
    }
    rows <- lapply(messages, function(message) {
      if (is.list(message)) {
        data.frame(
          role = as.character(message$role %||% "user"),
          content = as.character(message$content %||% message$text %||% ""),
          stringsAsFactors = FALSE
        )
      } else {
        data.frame(
          role = "user",
          content = as.character(message),
          stringsAsFactors = FALSE
        )
      }
    })
    return(do.call(rbind, rows))
  }
  cli::cli_abort("{.arg messages} must be a data frame, list, or character vector.")
}

.infer_conversation_content_col <- function(data) {
  preferred <- c("content", "text", "message", "prompt", "output")
  hit <- preferred[preferred %in% names(data)]
  if (length(hit) > 0L) {
    return(hit[[1L]])
  }
  chr_cols <- names(data)[vapply(data, is.character, logical(1))]
  chr_cols <- setdiff(chr_cols, "role")
  if (length(chr_cols) == 0L) {
    cli::cli_abort("{.arg messages} must contain a character content column.")
  }
  chr_cols[[1L]]
}
