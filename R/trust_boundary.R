#' Wrap a chat object in a trust boundary
#'
#' Validates chat identity before calls cross into an LLM service. This
#' covers supply-chain and model-integrity concerns related to OWASP LLM03; see
#' <https://genai.owasp.org/llm-top-10/>.
#'
#' @details
#' `trust_boundary()` returns a chat wrapper. The wrapper validates the chat on
#' creation and again on each call when `require_hash` is supplied. Plain
#' functions are passed through without model or host checks because a function
#' has no standard model metadata. Chat objects with a `$chat()` method may
#' expose model and host fields through common ellmer-style internals or
#' attributes.
#'
#' `allowed_models` and `allowed_hosts` are allowlists. If the chat exposes a
#' model or host and it is outside the allowlist, the wrapper raises an OWASP
#' LLM03 error. `require_hash` is intended for local Ollama workflows where the
#' model manifest can be checked with `ollama show --modelfile`.
#'
#' This function is not a network firewall. It is an application-level
#' assertion that the chat object being called is the chat object you intended
#' to allow.
#'
#' @param chat An `ellmer` chat object, an object with `$chat()`, or a function.
#' @param allowed_models Optional character vector of allowed model names.
#' @param allowed_hosts Optional character vector of allowed hosts or base URLs.
#' @param require_hash Optional expected SHA-256 hash for an Ollama modelfile
#'   manifest.
#' @param ... Reserved for backwards-compatible aliases.
#'
#' @return A callable chat wrapper.
#' @examples
#' chat <- function(prompt) paste("ok:", prompt)
#' safe_chat <- trust_boundary(chat)
#' safe_chat("hello")
#' @export
trust_boundary <- function(chat = NULL,
                           allowed_models = NULL,
                           allowed_hosts = NULL,
                           require_hash = NULL,
                           ...) {
  chat <- .resolve_chat_arg(chat, list(...))
  .validate_chat(chat)
  if (!is.null(allowed_models) && !is.character(allowed_models)) {
    cli::cli_abort("{.arg allowed_models} must be a character vector or {.code NULL}.")
  }
  if (!is.null(allowed_hosts) && !is.character(allowed_hosts)) {
    cli::cli_abort("{.arg allowed_hosts} must be a character vector or {.code NULL}.")
  }
  if (!is.null(require_hash)) {
    .check_string(require_hash, "require_hash")
  }

  validated <- FALSE
  validate <- function() {
    plain_function <- is.function(chat) && !.has_chat_method(chat)
    model <- .chat_model(chat)
    host <- .chat_host(chat)

    if (!plain_function && !is.null(allowed_models)) {
      if (is.null(model) || !model %in% allowed_models) {
        cli::cli_abort(
          "OWASP LLM03 trust boundary failed: model {.val {model %||% '<unknown>'}} is not in the allowed model list."
        )
      }
    }

    if (!plain_function && !is.null(allowed_hosts)) {
      if (is.null(host) || !.host_allowed(host, allowed_hosts)) {
        cli::cli_abort(
          "OWASP LLM03 trust boundary failed: host {.val {host %||% '<unknown>'}} is not in the allowed host list."
        )
      }
    }

    if (!is.null(require_hash)) {
      actual_hash <- .ollama_modelfile_hash(model)
      if (!identical(tolower(actual_hash), tolower(require_hash))) {
        cli::cli_abort("OWASP LLM03 trust boundary failed: Ollama model hash did not match {.arg require_hash}.")
      }
    }

    validated <<- TRUE
    TRUE
  }

  validate()

  function(...) {
    if (!validated || !is.null(require_hash)) {
      validate()
    }
    args <- list(...)
    if (length(args) == 0L) {
      return(chat)
    }
    if (is.function(chat)) {
      return(chat(...))
    }
    chat$chat(...)
  }
}

.has_chat_method <- function(chat) {
  method <- tryCatch(chat$chat, error = function(e) NULL)
  !is.null(method) && is.function(method)
}

.chat_model <- function(chat) {
  candidates <- list(
    attr(chat, "model", exact = TRUE),
    .pluck_chat(chat, "model"),
    .pluck_chat(chat, c(".__enclos_env__", "private", "model")),
    .pluck_chat(chat, c(".__enclos_env__", "private", ".model")),
    .pluck_chat(chat, c("private", "model"))
  )
  out <- .compact_chr(unlist(candidates, use.names = FALSE))
  if (length(out) == 0L) NULL else out[[1]]
}

.chat_host <- function(chat) {
  candidates <- list(
    attr(chat, "base_url", exact = TRUE),
    attr(chat, "host", exact = TRUE),
    .pluck_chat(chat, "base_url"),
    .pluck_chat(chat, "host"),
    .pluck_chat(chat, "url"),
    .pluck_chat(chat, c(".__enclos_env__", "private", "base_url")),
    .pluck_chat(chat, c(".__enclos_env__", "private", "host")),
    .pluck_chat(chat, c(".__enclos_env__", "private", "url")),
    .pluck_chat(chat, c("private", "base_url")),
    .pluck_chat(chat, c("private", "host"))
  )
  out <- .compact_chr(unlist(candidates, use.names = FALSE))
  if (length(out) == 0L) NULL else out[[1]]
}

.pluck_chat <- function(x, path) {
  current <- x
  for (key in path) {
    current <- tryCatch(current[[key]], error = function(e) NULL)
    if (is.null(current)) {
      return(NULL)
    }
  }
  current
}

.host_allowed <- function(host, allowed_hosts) {
  parsed <- tryCatch(utils::URLdecode(host), error = function(e) host)
  host_only <- sub("^https?://", "", parsed, ignore.case = TRUE)
  host_only <- sub("/.*$", "", host_only)
  host %in% allowed_hosts || parsed %in% allowed_hosts || host_only %in% allowed_hosts
}

.ollama_modelfile_hash <- function(model) {
  if (is.null(model)) {
    cli::cli_abort("OWASP LLM03 trust boundary failed: cannot verify a hash without a model name.")
  }
  manifest <- tryCatch(
    system2("ollama", c("show", "--modelfile", model), stdout = TRUE, stderr = TRUE),
    error = function(e) {
      cli::cli_abort("OWASP LLM03 trust boundary failed: could not call {.code ollama show --modelfile}.")
    }
  )
  status <- attr(manifest, "status")
  if (!is.null(status) && !identical(status, 0L)) {
    cli::cli_abort("OWASP LLM03 trust boundary failed: Ollama returned a non-zero status.")
  }
  digest::digest(paste(manifest, collapse = "\n"), algo = "sha256", serialize = FALSE)
}
