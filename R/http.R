# Reserved for future HTTP-oriented integrations (remote policy fetch, etc.)
# TODO: implement remote policy loading via httr2 when needed.

.check_httr2 <- function() {
  rlang::check_installed("httr2",
    reason = "for HTTP-based llmshieldr integrations"
  )
}
