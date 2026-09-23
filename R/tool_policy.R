#' Define authorization and limits for model tools
#'
#' Tool policy combines a default-deny allowlist with per-tool argument schemas,
#' subject authorization, custom validators, and call, side-effect, and spend
#' limits. Custom validators receive `(arguments, subject, tool_name)` and must
#' return `TRUE`, `FALSE`, a message, or `list(valid, message)`.
#'
#' @param allowed_tools Explicit tool allowlist.
#' @param schemas Named list of compact JSON-Schema-like lists or validator
#'   functions. Supported schema fields are `required`, `properties`, and
#'   `additionalProperties`; property fields include `type`, `enum`, `pattern`,
#'   `minimum`, and `maximum`.
#' @param authorize Optional function receiving `(subject, tool_name, arguments)`.
#' @param validators Named list of additional per-tool validator functions.
#' @param side_effect_tools Tools counted against `max_side_effects`.
#' @param max_calls Maximum tool requests in one guarded chat.
#' @param max_side_effects Maximum side-effecting requests in one guarded chat.
#' @param spend_limits Named numeric vector of maximum spend per tool.
#' @param spend_argument Name of the numeric argument carrying spend.
#' @param show_stats Show construction time and available usage metrics.
#'
#' @return A `shieldr_tool_policy` object.
#' @examples
#' tools <- tool_policy(
#'   allowed_tools = "search_docs",
#'   schemas = list(search_docs = list(
#'     required = "query",
#'     properties = list(query = list(type = "string")),
#'     additionalProperties = FALSE
#'   )),
#'   max_calls = 3
#' )
#' @export
tool_policy <- function(allowed_tools = character(),
                        schemas = list(),
                        authorize = NULL,
                        validators = list(),
                        side_effect_tools = character(),
                        max_calls = Inf,
                        max_side_effects = 0L,
                        spend_limits = numeric(),
                        spend_argument = "amount",
                        show_stats = FALSE) {
  stats <- .stats_begin(show_stats, "tool_policy")
  on.exit(.stats_end(stats), add = TRUE)
  for (item in c("allowed_tools", "side_effect_tools")) {
    value <- get(item)
    if (!is.character(value) || anyNA(value)) cli::cli_abort("{.arg {item}} must be a character vector without missing values.")
  }
  for (item in c("schemas", "validators")) {
    value <- get(item)
    if (!is.list(value) || (length(value) > 0L && (is.null(names(value)) || any(!nzchar(names(value)))))) {
      cli::cli_abort("{.arg {item}} must be a named list.")
    }
  }
  if (any(!vapply(validators, is.function, logical(1)))) cli::cli_abort("Every {.arg validators} entry must be a function.")
  if (!is.null(authorize) && !is.function(authorize)) cli::cli_abort("{.arg authorize} must be a function or {.code NULL}.")
  if (!is.numeric(max_calls) || length(max_calls) != 1L || is.na(max_calls) || max_calls < 0) cli::cli_abort("{.arg max_calls} must be a non-negative number.")
  if (!is.numeric(max_side_effects) || length(max_side_effects) != 1L || is.na(max_side_effects) || max_side_effects < 0) cli::cli_abort("{.arg max_side_effects} must be a non-negative number.")
  if (!is.numeric(spend_limits) || anyNA(spend_limits) || any(spend_limits < 0) || (length(spend_limits) > 0L && (is.null(names(spend_limits)) || any(!nzchar(names(spend_limits)))))) {
    cli::cli_abort("{.arg spend_limits} must be a non-negative named numeric vector.")
  }
  .check_string(spend_argument, "spend_argument")
  structure(
    list(
      allowed_tools = unique(allowed_tools),
      schemas = schemas,
      authorize = authorize,
      validators = validators,
      side_effect_tools = unique(side_effect_tools),
      max_calls = max_calls,
      max_side_effects = max_side_effects,
      spend_limits = spend_limits,
      spend_argument = spend_argument
    ),
    class = "shieldr_tool_policy"
  )
}

#' Dispatch one tool through guardrails
#'
#' Scans arguments, executes only an allowed request, then scans the tool result
#' before returning it. This is the provider-neutral dispatcher for chat SDKs
#' that do not expose request/result hooks.
#'
#' @param tool_name Tool name.
#' @param arguments Named argument list.
#' @param dispatcher Function accepting `(tool_name, arguments)`, or a named
#'   list of tool functions called with `do.call()`.
#' @param tool_policy Policy from [tool_policy()].
#' @param subject Optional authorization context passed through unchanged.
#' @inheritParams scan_tool_call
#' @param show_stats Show execution statistics as messages.
#'
#' @return A list with `action`, `value`, `call_report`, and `output_report`.
#' @examples
#' dispatcher <- list(search = function(query) paste("result", query))
#' guard_tool(
#'   "search", list(query = "public"), dispatcher,
#'   tool_policy(allowed_tools = "search")
#' )
#' @export
guard_tool <- function(tool_name,
                       arguments = list(),
                       dispatcher,
                       tool_policy,
                       subject = NULL,
                       policy = "enterprise_default",
                       reviewer = NULL,
                       checks = "rules",
                       redaction = NULL,
                       scanners = scanner_options(),
                       show_tokens = FALSE,
                       show_stats = FALSE) {
  stats <- .stats_begin(show_stats, "guard_tool")
  on.exit(.stats_end(stats), add = TRUE)
  .validate_tool_policy(tool_policy)
  state <- .tool_policy_state()
  call_report <- scan_tool_call(
    tool_name, arguments, tool_policy = tool_policy, subject = subject,
    state = state, policy = policy, reviewer = reviewer, checks = checks,
    redaction = redaction, scanners = scanners, show_tokens = show_tokens
  )
  if (!identical(call_report$action, "allow")) {
    return(list(action = "block", value = NULL, call_report = call_report, output_report = NULL))
  }
  value <- if (is.function(dispatcher)) {
    dispatcher(tool_name, arguments)
  } else if (is.list(dispatcher) && is.function(dispatcher[[tool_name]])) {
    do.call(dispatcher[[tool_name]], arguments)
  } else {
    cli::cli_abort("{.arg dispatcher} must be a function or a named list containing the requested tool.")
  }
  output_report <- scan_tool_output(
    tool_name, value, policy = policy, reviewer = reviewer, checks = checks,
    redaction = redaction, scanners = scanners, show_tokens = show_tokens
  )
  list(
    action = if (identical(output_report$action, "allow")) "allow" else "block",
    value = if (identical(output_report$action, "allow")) value else NULL,
    call_report = call_report,
    output_report = output_report
  )
}

.validate_tool_policy <- function(x, allow_null = FALSE) {
  if (is.null(x) && isTRUE(allow_null)) return(invisible(TRUE))
  if (!inherits(x, "shieldr_tool_policy")) cli::cli_abort("{.arg tool_policy} must be created by {.fn tool_policy}.")
  invisible(TRUE)
}

.as_tool_policy <- function(x, allowed_tools = character()) {
  if (is.null(x)) return(tool_policy(allowed_tools = allowed_tools, max_calls = Inf, max_side_effects = Inf))
  .validate_tool_policy(x)
  x
}

.tool_policy_state <- function() {
  state <- new.env(parent = emptyenv())
  state$calls <- 0L
  state$side_effects <- 0L
  state
}

.tool_policy_findings <- function(name, arguments, policy, subject, state = NULL) {
  findings <- list()
  reject <- function(id, description) {
    findings[[length(findings) + 1L]] <<- .synthetic_finding(id, "llm03", "critical", description, action = "block")
  }
  if (!name %in% policy$allowed_tools) reject("llm03.tool.unapproved", "Tool call targets a tool outside the configured allowlist.")
  if (!is.list(arguments)) reject("llm03.tool.arguments", "Tool arguments must be represented as a list for schema and authorization checks.")
  if (is.list(arguments) && name %in% names(policy$schemas)) {
    result <- .validate_tool_schema(arguments, policy$schemas[[name]])
    if (!result$valid) reject("llm03.tool.schema", paste0("Tool arguments failed schema validation: ", result$message))
  }
  if (!is.null(policy$authorize)) {
    result <- tryCatch(policy$authorize(subject, name, arguments), error = identity)
    valid <- !inherits(result, "error") && isTRUE(if (is.list(result)) result$authorized %||% result$valid else result)
    if (!valid) reject("llm03.tool.authorization", "The subject is not authorized for this tool request.")
  }
  if (is.list(arguments) && name %in% names(policy$validators)) {
    result <- tryCatch(policy$validators[[name]](arguments, subject, name), error = identity)
    valid <- !inherits(result, "error") && isTRUE(if (is.list(result)) result$valid else result)
    if (!valid) {
      message <- if (is.list(result)) result$message %||% "custom validation failed" else if (is.character(result)) result[[1L]] else "custom validation failed"
      reject("llm03.tool.validator", paste0("Tool request failed custom validation: ", message, "."))
    }
  }
  if (is.list(arguments) && name %in% names(policy$spend_limits)) {
    spend <- suppressWarnings(as.numeric(arguments[[policy$spend_argument]] %||% NA_real_))
    if (length(spend) != 1L || !is.finite(spend) || spend < 0 || spend > policy$spend_limits[[name]]) {
      reject("llm03.tool.spend", "Tool request exceeds or omits the configured spend limit.")
    }
  }
  if (!is.null(state)) {
    projected_calls <- state$calls + 1L
    projected_side_effects <- state$side_effects + as.integer(name %in% policy$side_effect_tools)
    if (projected_calls > policy$max_calls) reject("llm06.tool.call_limit", "Tool request exceeds the configured call limit.")
    if (projected_side_effects > policy$max_side_effects) reject("llm03.tool.side_effect_limit", "Tool request exceeds the configured side-effect limit.")
    if (length(findings) == 0L) {
      state$calls <- projected_calls
      state$side_effects <- projected_side_effects
    }
  }
  findings
}

.validate_tool_schema <- function(arguments, schema) {
  if (is.function(schema)) {
    result <- tryCatch(schema(arguments), error = identity)
    if (inherits(result, "error")) return(list(valid = FALSE, message = conditionMessage(result)))
    valid <- isTRUE(if (is.list(result)) result$valid else result)
    message <- if (is.list(result)) result$message %||% "custom schema rejected arguments" else if (is.character(result)) result[[1L]] else "custom schema rejected arguments"
    return(list(valid = valid, message = message))
  }
  if (!is.list(schema)) return(list(valid = FALSE, message = "schema is not a list or function"))
  required <- schema$required %||% character()
  missing <- setdiff(required, names(arguments))
  if (length(missing) > 0L) return(list(valid = FALSE, message = paste0("missing required properties: ", paste(missing, collapse = ", "))))
  properties <- schema$properties %||% list()
  if (identical(schema$additionalProperties, FALSE)) {
    extra <- setdiff(names(arguments), names(properties))
    if (length(extra) > 0L) return(list(valid = FALSE, message = paste0("unexpected properties: ", paste(extra, collapse = ", "))))
  }
  for (name in intersect(names(arguments), names(properties))) {
    result <- .validate_tool_property(arguments[[name]], properties[[name]], name)
    if (!result$valid) return(result)
  }
  list(valid = TRUE, message = "")
}

.validate_tool_property <- function(value, rule, name) {
  if (!is.list(rule)) return(list(valid = FALSE, message = paste0(name, " has an invalid schema")))
  types <- rule$type %||% NULL
  if (!is.null(types)) {
    checks <- c(
      string = is.character(value) && length(value) == 1L,
      number = is.numeric(value) && length(value) == 1L,
      integer = is.numeric(value) && length(value) == 1L && value == floor(value),
      boolean = is.logical(value) && length(value) == 1L,
      array = is.atomic(value) || (is.list(value) && is.null(names(value))),
      object = is.list(value) && !is.null(names(value)),
      null = is.null(value)
    )
    if (!any(checks[intersect(types, names(checks))])) return(list(valid = FALSE, message = paste0(name, " has the wrong type")))
  }
  if (!is.null(rule$enum) && !any(vapply(rule$enum, identical, logical(1), value))) return(list(valid = FALSE, message = paste0(name, " is outside its enum")))
  if (!is.null(rule$pattern) && (!is.character(value) || length(value) != 1L || !grepl(rule$pattern, value, perl = TRUE))) return(list(valid = FALSE, message = paste0(name, " does not match its pattern")))
  if (!is.null(rule$minimum) && (!is.numeric(value) || value < rule$minimum)) return(list(valid = FALSE, message = paste0(name, " is below its minimum")))
  if (!is.null(rule$maximum) && (!is.numeric(value) || value > rule$maximum)) return(list(valid = FALSE, message = paste0(name, " exceeds its maximum")))
  list(valid = TRUE, message = "")
}
