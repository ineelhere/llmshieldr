test_that("plain functions pass through trust boundary", {
  provider <- function(prompt) paste("ok", prompt)
  safe <- trust_boundary(provider, allowed_models = "ignored-for-functions")

  expect_equal(safe("hello"), "ok hello")
})

test_that("wrong model names fail with LLM03 message", {
  provider <- list(
    chat = function(prompt) prompt,
    .__enclos_env__ = list(private = list(model = "bad-model"))
  )

  expect_error(trust_boundary(provider, allowed_models = "good-model"), "LLM03")
})
