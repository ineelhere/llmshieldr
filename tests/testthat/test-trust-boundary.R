test_that("plain functions pass through trust boundary", {
  chat <- function(prompt) paste("ok", prompt)
  safe <- trust_boundary(chat, allowed_models = "ignored-for-functions")

  expect_equal(safe("hello"), "ok hello")
})

test_that("wrong model names fail with LLM03 message", {
  chat <- list(
    chat = function(prompt) prompt,
    .__enclos_env__ = list(private = list(model = "bad-model"))
  )

  expect_error(trust_boundary(chat, allowed_models = "good-model"), "LLM03")
})
