#' Define retrieved-context admission requirements
#'
#' Context policy checks provenance and authorization metadata after retrieval.
#' Applications must also enforce tenant and ACL scope inside the retrieval
#' query so unauthorized rows are never selected in the first place.
#'
#' @param required_columns Metadata columns that must exist and be non-missing.
#' @param tenant_id Optional tenant required for every row.
#' @param tenant_col Tenant column name.
#' @param principals Optional subject or role identifiers.
#' @param acl_col Optional ACL column. Values may be character vectors, list
#'   column entries, or comma-separated strings.
#' @param trusted_sources Optional source allowlist.
#' @param source_col Source column name.
#' @param allowed_trust_tiers Optional trust-tier allowlist.
#' @param trust_col Trust-tier column name.
#' @param max_age_seconds Optional maximum context age.
#' @param timestamp_col Freshness timestamp column name.
#' @param authorize Optional final row authorization function.
#' @param now Function returning the current time, useful for deterministic tests.
#' @param show_stats Show construction time and available usage metrics.
#'
#' @return A `shieldr_context_policy` object.
#' @examples
#' admission <- context_policy(
#'   required_columns = c("document_id", "source", "tenant"),
#'   tenant_id = "tenant-a"
#' )
#' @export
context_policy <- function(required_columns = c("document_id", "source"),
                           tenant_id = NULL,
                           tenant_col = "tenant",
                           principals = NULL,
                           acl_col = NULL,
                           trusted_sources = NULL,
                           source_col = "source",
                           allowed_trust_tiers = NULL,
                           trust_col = "trust_tier",
                           max_age_seconds = NULL,
                           timestamp_col = "updated_at",
                           authorize = NULL,
                           now = Sys.time,
                           show_stats = FALSE) {
  stats <- .stats_begin(show_stats, "context_policy")
  on.exit(.stats_end(stats), add = TRUE)
  char_args <- list(
    required_columns = required_columns, principals = principals,
    trusted_sources = trusted_sources, allowed_trust_tiers = allowed_trust_tiers
  )
  for (name in names(char_args)) {
    value <- char_args[[name]]
    if (!is.null(value) && (!is.character(value) || anyNA(value))) {
      cli::cli_abort("{.arg {name}} must be a character vector without missing values or {.code NULL}.")
    }
  }
  for (name in c("tenant_col", "source_col", "trust_col", "timestamp_col")) {
    .check_string(get(name), name)
  }
  if (!is.null(tenant_id)) .check_string(tenant_id, "tenant_id")
  if (!is.null(acl_col)) .check_string(acl_col, "acl_col")
  .validate_nullable_limit(max_age_seconds, "max_age_seconds")
  if (!is.null(authorize) && !is.function(authorize)) cli::cli_abort("{.arg authorize} must be a function or {.code NULL}.")
  if (!is.function(now)) cli::cli_abort("{.arg now} must be a function.")
  structure(
    list(
      required_columns = unique(required_columns %||% character()),
      tenant_id = tenant_id,
      tenant_col = tenant_col,
      principals = unique(principals %||% character()),
      acl_col = acl_col,
      trusted_sources = trusted_sources,
      source_col = source_col,
      allowed_trust_tiers = allowed_trust_tiers,
      trust_col = trust_col,
      max_age_seconds = max_age_seconds,
      timestamp_col = timestamp_col,
      authorize = authorize,
      now = now
    ),
    class = "shieldr_context_policy"
  )
}

.validate_context_policy <- function(x, allow_null = FALSE) {
  if (is.null(x) && isTRUE(allow_null)) return(invisible(TRUE))
  if (!inherits(x, "shieldr_context_policy")) {
    cli::cli_abort("{.arg context_policy} must be created by {.fn context_policy}.")
  }
  invisible(TRUE)
}

.context_policy_columns <- function(policy) {
  unique(c(
    policy$required_columns,
    if (!is.null(policy$tenant_id)) policy$tenant_col,
    if (!is.null(policy$acl_col)) policy$acl_col,
    if (!is.null(policy$trusted_sources)) policy$source_col,
    if (!is.null(policy$allowed_trust_tiers)) policy$trust_col,
    if (!is.null(policy$max_age_seconds)) policy$timestamp_col
  ))
}

.context_policy_admission <- function(row, policy) {
  reasons <- character()
  required <- .context_policy_columns(policy)
  missing_columns <- setdiff(required, names(row))
  if (length(missing_columns) > 0L) reasons <- c(reasons, paste0("missing_columns:", paste(missing_columns, collapse = ",")))
  present_required <- intersect(policy$required_columns, names(row))
  if (length(present_required) > 0L) {
    missing_values <- present_required[vapply(row[present_required], function(x) {
      length(x) == 0L || all(is.na(x)) || (is.character(x) && all(!nzchar(trimws(x))))
    }, logical(1))]
    if (length(missing_values) > 0L) reasons <- c(reasons, paste0("missing_values:", paste(missing_values, collapse = ",")))
  }
  if (!is.null(policy$tenant_id) && policy$tenant_col %in% names(row)) {
    if (!identical(as.character(row[[policy$tenant_col]][[1L]]), policy$tenant_id)) reasons <- c(reasons, "tenant")
  }
  if (!is.null(policy$acl_col) && policy$acl_col %in% names(row)) {
    acl <- row[[policy$acl_col]][[1L]]
    acl <- if (is.list(acl)) unlist(acl, use.names = FALSE) else unlist(strsplit(as.character(acl), "[,;]", perl = TRUE), use.names = FALSE)
    acl <- trimws(as.character(acl))
    if (length(intersect(acl, policy$principals)) == 0L) reasons <- c(reasons, "acl")
  }
  if (!is.null(policy$trusted_sources) && policy$source_col %in% names(row)) {
    source <- as.character(row[[policy$source_col]][[1L]])
    if (is.na(source) || !source %in% policy$trusted_sources) reasons <- c(reasons, "source")
  }
  if (!is.null(policy$allowed_trust_tiers) && policy$trust_col %in% names(row)) {
    tier <- as.character(row[[policy$trust_col]][[1L]])
    if (is.na(tier) || !tier %in% policy$allowed_trust_tiers) reasons <- c(reasons, "trust_tier")
  }
  if (!is.null(policy$max_age_seconds) && policy$timestamp_col %in% names(row)) {
    stamp <- suppressWarnings(as.POSIXct(row[[policy$timestamp_col]][[1L]], tz = "UTC"))
    current <- suppressWarnings(as.POSIXct(policy$now(), tz = "UTC"))
    age <- as.numeric(difftime(current, stamp, units = "secs"))
    if (!is.finite(age) || age < 0 || age > policy$max_age_seconds) reasons <- c(reasons, "freshness")
  }
  if (!is.null(policy$authorize)) {
    authorized <- isTRUE(tryCatch(policy$authorize(row), error = function(e) FALSE))
    if (!authorized) reasons <- c(reasons, "authorization")
  }
  list(admit = length(reasons) == 0L, reasons = unique(reasons))
}
