#' Configure URL destination policy
#'
#' Defines canonical URL checks for text scanners and for application code that
#' is about to make a network request. The policy can also validate resolved IP
#' addresses and redirect targets supplied by the network executor.
#'
#' @param allowed_schemes Allowed schemes.
#' @param allowed_hosts Optional exact host allowlist.
#' @param blocked_hosts Exact blocked hosts. Subdomains are also blocked.
#' @param allow_userinfo Whether `user:password@host` authorities are allowed.
#' @param allow_idn Whether non-ASCII and punycode host names are allowed.
#' @param block_private Whether loopback, link-local, and private IP targets are
#'   blocked, including executor-supplied DNS results.
#' @param max_redirects Maximum redirect targets accepted by [scan_url_target()].
#' @param show_stats Show construction time and available usage metrics.
#'
#' @return A `shieldr_url_policy` object.
#' @examples
#' policy <- url_policy(allowed_hosts = "api.example.com")
#' scan_url_target("https://api.example.com/v1", policy)
#' @export
url_policy <- function(allowed_schemes = "https",
                       allowed_hosts = NULL,
                       blocked_hosts = c("localhost", "localhost.localdomain"),
                       allow_userinfo = FALSE,
                       allow_idn = FALSE,
                       block_private = TRUE,
                       max_redirects = 0L,
                       show_stats = FALSE) {
  stats <- .stats_begin(show_stats, "url_policy")
  on.exit(.stats_end(stats), add = TRUE)
  if (!is.character(allowed_schemes) || length(allowed_schemes) == 0L || anyNA(allowed_schemes)) {
    cli::cli_abort("{.arg allowed_schemes} must be a non-empty character vector.")
  }
  if (!is.null(allowed_hosts) && (!is.character(allowed_hosts) || anyNA(allowed_hosts))) {
    cli::cli_abort("{.arg allowed_hosts} must be a character vector or {.code NULL}.")
  }
  if (!is.character(blocked_hosts) || anyNA(blocked_hosts)) {
    cli::cli_abort("{.arg blocked_hosts} must be a character vector.")
  }
  .validate_flag(allow_userinfo, "allow_userinfo")
  .validate_flag(allow_idn, "allow_idn")
  .validate_flag(block_private, "block_private")
  .validate_count(max_redirects, "max_redirects")
  structure(
    list(
      allowed_schemes = unique(tolower(allowed_schemes)),
      allowed_hosts = if (is.null(allowed_hosts)) NULL else unique(.canonical_host(allowed_hosts)),
      blocked_hosts = unique(.canonical_host(blocked_hosts)),
      allow_userinfo = allow_userinfo,
      allow_idn = allow_idn,
      block_private = block_private,
      max_redirects = as.integer(max_redirects)
    ),
    class = "shieldr_url_policy"
  )
}

#' Check a URL immediately before network use
#'
#' This function performs no request and no DNS lookup. Pass IP addresses from
#' the executor's resolver and every redirect target so policy is rechecked at
#' the same boundary that will connect to the destination.
#'
#' @param url Requested URL.
#' @param policy Policy from [url_policy()].
#' @param resolved_ips Optional IP addresses returned by the executor's DNS
#'   resolver.
#' @param redirect_chain Optional redirect target URLs in observed order.
#' @param show_stats Show execution statistics as messages.
#'
#' @return A `shieldr_report`.
#' @examples
#' scan_url_target("https://example.com")
#' scan_url_target("http://127.0.0.1/admin")$action
#' @export
scan_url_target <- function(url,
                            policy = url_policy(allowed_schemes = c("http", "https")),
                            resolved_ips = NULL,
                            redirect_chain = character(),
                            show_stats = FALSE) {
  stats <- .stats_begin(show_stats, "scan_url_target")
  on.exit(.stats_end(stats), add = TRUE)
  .check_string(url, "url")
  .validate_url_policy(policy)
  if (!is.null(resolved_ips) && (!is.character(resolved_ips) || anyNA(resolved_ips))) {
    cli::cli_abort("{.arg resolved_ips} must be a character vector or {.code NULL}.")
  }
  if (!is.character(redirect_chain) || anyNA(redirect_chain)) {
    cli::cli_abort("{.arg redirect_chain} must be a character vector without missing values.")
  }
  .stats_text_tokens(stats, url)
  findings <- .url_policy_findings(url, policy, resolved_ips, redirect_chain)
  risk <- .score_findings(findings)
  minimal <- shieldr_policy(
    "url_policy", list(), list(redact_at = 0.3, block_at = 0.7)
  )
  shieldr_report(
    action = .resolve_action(risk, findings, minimal),
    text_clean = url,
    findings = findings,
    risk_score = risk,
    policy = "url_policy",
    checks = "rules",
    metadata = .report_metadata(
      stage = "url_target",
      resolved_ip_count = length(resolved_ips %||% character()),
      redirect_count = length(redirect_chain)
    )
  )
}

.validate_url_policy <- function(x) {
  if (!inherits(x, "shieldr_url_policy")) {
    cli::cli_abort("{.arg url_policy} must be created by {.fn url_policy}.")
  }
  invisible(TRUE)
}

.url_policy_findings <- function(url, policy, resolved_ips = NULL, redirect_chain = character()) {
  parsed <- .parse_url(url)
  findings <- list()
  add <- function(id, description) {
    finding <- .scanner_finding(id, "llm03", "critical", "block", description, url)
    findings[[length(findings) + 1L]] <<- finding
  }
  if (!isTRUE(parsed$valid)) {
    add("llm03.url.invalid", paste0("URL is invalid or ambiguous: ", parsed$reason, "."))
    return(findings)
  }
  if (!parsed$scheme %in% policy$allowed_schemes) {
    add("llm03.url.scheme", "URL scheme is outside the configured allowlist.")
  }
  if (parsed$has_userinfo && !isTRUE(policy$allow_userinfo)) {
    add("llm03.url.userinfo", "URL user-info is not allowed.")
  }
  if ((parsed$is_idn || grepl("(^|\\.)xn--", parsed$host)) && !isTRUE(policy$allow_idn)) {
    add("llm03.url.idn", "Internationalized or punycode host is not allowed.")
  }
  if (.host_matches(parsed$host, policy$blocked_hosts)) {
    add("llm03.url.blocked_host", "URL host is blocked.")
  }
  if (!is.null(policy$allowed_hosts) && !parsed$host %in% policy$allowed_hosts) {
    add("llm03.url.host_allowlist", "URL host is outside the configured allowlist.")
  }
  if (isTRUE(policy$block_private) && .is_private_target(parsed$host)) {
    add("llm03.url.private_target", "URL resolves syntactically to a local or private target.")
  }
  if (isTRUE(policy$block_private) && length(resolved_ips) > 0L && any(vapply(resolved_ips, .is_private_target, logical(1)))) {
    add("llm03.url.private_dns", "Executor DNS results contain a local or private address.")
  }
  if (length(redirect_chain) > policy$max_redirects) {
    add("llm03.url.redirect_limit", "URL redirect count exceeds the configured limit.")
  }
  for (redirect in utils::head(redirect_chain, policy$max_redirects)) {
    nested <- .url_policy_findings(redirect, policy, NULL, character())
    if (length(nested) > 0L) {
      nested <- lapply(nested, function(finding) {
        finding$rule_id <- paste0(finding$rule_id, ".redirect")
        finding$description <- paste("Redirect target rejected.", finding$description)
        finding
      })
      findings <- c(findings, nested)
    }
  }
  .dedupe_findings(findings)
}

.parse_url <- function(url) {
  decoded <- url
  for (i in 1:2) {
    next_value <- tryCatch(utils::URLdecode(decoded), error = function(e) decoded)
    if (identical(next_value, decoded)) break
    decoded <- next_value
  }
  if (grepl("[\\\\\r\n\t]", decoded, perl = TRUE)) {
    return(list(valid = FALSE, reason = "control character or backslash"))
  }
  parts <- regexec("^([A-Za-z][A-Za-z0-9+.-]*)://([^/?#]*)(?:[/?#]|$)", decoded, perl = TRUE)
  hit <- regmatches(decoded, parts)[[1L]]
  if (length(hit) < 3L) return(list(valid = FALSE, reason = "missing scheme or authority"))
  scheme <- tolower(hit[[2L]])
  authority <- hit[[3L]]
  has_userinfo <- grepl("@", authority, fixed = TRUE)
  host_port <- sub("^.*@", "", authority)
  if (grepl("^\\[", host_port)) {
    close <- regexpr("\\]", host_port, perl = TRUE)[[1L]]
    if (close < 0L) return(list(valid = FALSE, reason = "malformed IPv6 authority"))
    host <- substr(host_port, 2L, close - 1L)
    suffix <- substr(host_port, close + 1L, nchar(host_port))
    if (nzchar(suffix) && !grepl("^:[0-9]+$", suffix)) {
      return(list(valid = FALSE, reason = "malformed port"))
    }
  } else {
    if (length(gregexpr(":", host_port, fixed = TRUE)[[1L]]) > 1L) {
      return(list(valid = FALSE, reason = "unbracketed IPv6 address"))
    }
    host <- sub(":([0-9]+)$", "", host_port)
    if (grepl(":", host, fixed = TRUE)) return(list(valid = FALSE, reason = "malformed port"))
  }
  host <- .canonical_host(host)
  if (!nzchar(host)) return(list(valid = FALSE, reason = "empty host"))
  list(
    valid = TRUE, scheme = scheme, host = host, has_userinfo = has_userinfo,
    is_idn = grepl("[^\x01-\x7F]", host, perl = TRUE)
  )
}

.canonical_host <- function(host) {
  tolower(sub("\\.$", "", trimws(host)))
}

.host_matches <- function(host, entries) {
  any(vapply(entries, function(entry) {
    identical(host, entry) || endsWith(host, paste0(".", entry))
  }, logical(1)))
}

.is_private_target <- function(host) {
  host <- tolower(gsub("^\\[|\\]$", "", host))
  if (host %in% c("localhost", "localhost.localdomain", "::", "::1") || endsWith(host, ".localhost")) {
    return(TRUE)
  }
  if (grepl("^(fc|fd|fe8|fe9|fea|feb)", host) && grepl(":", host, fixed = TRUE)) return(TRUE)
  if (grepl("^::ffff:", host)) return(.is_private_target(sub("^::ffff:", "", host)))
  if (grepl("^0x[0-9a-f]+$", host)) {
    value <- suppressWarnings(strtoi(sub("^0x", "", host), base = 16L))
    if (!is.na(value)) host <- paste((value %/% c(16777216, 65536, 256, 1)) %% 256, collapse = ".")
  } else if (grepl("^[0-9]+$", host)) {
    value <- suppressWarnings(as.numeric(host))
    if (is.finite(value) && value >= 0 && value <= 4294967295) {
      host <- paste(floor(value / c(16777216, 65536, 256, 1)) %% 256, collapse = ".")
    }
  }
  if (!grepl("^[0-9]{1,3}(\\.[0-9]{1,3}){3}$", host)) return(FALSE)
  octets <- suppressWarnings(as.integer(strsplit(host, ".", fixed = TRUE)[[1L]]))
  if (anyNA(octets) || any(octets > 255L)) return(TRUE)
  octets[[1L]] == 10L || octets[[1L]] == 127L || octets[[1L]] == 0L ||
    (octets[[1L]] == 169L && octets[[2L]] == 254L) ||
    (octets[[1L]] == 172L && octets[[2L]] >= 16L && octets[[2L]] <= 31L) ||
    (octets[[1L]] == 192L && octets[[2L]] == 168L) ||
    (octets[[1L]] == 100L && octets[[2L]] >= 64L && octets[[2L]] <= 127L)
}
