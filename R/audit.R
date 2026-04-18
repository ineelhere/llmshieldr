#' Audit class
#'
#' S3 class for audit logs
shield_audit <- function(...) {
  structure(list(...), class = "shield_audit")
}

#' Write audit log
#'
#' @param audit shield_audit object
#' @param file File path
write_audit_log <- function(audit, file) {
  jsonlite::write_json(audit, file, auto_unbox = TRUE)
}