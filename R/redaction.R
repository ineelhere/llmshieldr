#' Configure redaction behavior
#'
#' `redaction_strategy()` controls how scanner spans are rewritten in
#' `text_clean`. The default strategy preserves the original package behavior:
#' every matched span is replaced by `[REDACTED]`.
#'
#' @details
#' Redaction only applies to findings that include `start` and `end` character
#' offsets. Regex rules and some semantic reviewer schemas can provide spans.
#' Function rules and synthetic findings can still change score and action, but
#' they do not rewrite text unless they include span metadata.
#'
#' Supported operators:
#'
#' - `"replace"`: replace the span with `replacement`.
#' - `"mask"`: replace each character in the span with `mask`.
#' - `"hash"`: replace the span with a short deterministic digest label.
#' - `"drop"`: remove the span.
#' - `"keep"`: leave the span unchanged while still returning findings.
#'
#' Hash redaction is deterministic for the same matched string and algorithm,
#' which can help link repeated values without storing the original secret.
#' It is not anonymization and should still be treated as sensitive metadata.
#'
#' @param operator One of `"replace"`, `"mask"`, `"hash"`, `"drop"`, or
#'   `"keep"`.
#' @param replacement Replacement text used by `operator = "replace"`.
#' @param mask Single-character mask used by `operator = "mask"`.
#' @param hash_algo Digest algorithm passed to [digest::digest()] for
#'   `operator = "hash"`.
#' @param hash_prefix Number of digest characters to keep in hash labels.
#'
#' @return A `shieldr_redaction_strategy` object.
#' @examples
#' scan_prompt(
#'   "Email neel@example.com",
#'   redaction = redaction_strategy("mask", mask = "*")
#' )
#'
#' scan_prompt(
#'   "Email neel@example.com",
#'   redaction = redaction_strategy("hash")
#' )
#' @export
redaction_strategy <- function(operator = c("replace", "mask", "hash", "drop", "keep"),
                               replacement = "[REDACTED]",
                               mask = "*",
                               hash_algo = "sha256",
                               hash_prefix = 12L) {
  operator <- match.arg(operator)
  .check_string(replacement, "replacement", allow_empty = TRUE)
  .check_string(mask, "mask")
  if (nchar(mask, type = "chars") != 1L) {
    cli::cli_abort("{.arg mask} must be a single character.")
  }
  .check_string(hash_algo, "hash_algo")
  .validate_nullable_limit(hash_prefix, "hash_prefix", allow_null = FALSE)

  structure(
    list(
      operator = operator,
      replacement = replacement,
      mask = mask,
      hash_algo = hash_algo,
      hash_prefix = as.integer(hash_prefix)
    ),
    class = "shieldr_redaction_strategy"
  )
}

.validate_redaction_strategy <- function(redaction) {
  if (is.null(redaction)) {
    return(redaction_strategy())
  }
  if (!inherits(redaction, "shieldr_redaction_strategy")) {
    cli::cli_abort("{.arg redaction} must be created by {.fn redaction_strategy}.")
  }
  redaction
}

.redaction_replacement <- function(value, strategy) {
  switch(
    strategy$operator,
    replace = strategy$replacement,
    mask = paste(rep(strategy$mask, nchar(value, type = "chars")), collapse = ""),
    hash = {
      digest <- digest::digest(value, algo = strategy$hash_algo, serialize = FALSE)
      paste0("[HASH:", substr(digest, 1L, strategy$hash_prefix), "]")
    },
    drop = "",
    keep = value
  )
}
