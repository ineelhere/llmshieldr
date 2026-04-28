test_that("rate_guard creates and updates usage", {
  guard <- rate_guard(max_tokens = 100, max_requests = 10, cost_limit_usd = 1)
  guard$update(tokens = 10, cost_usd = 0.1)
  usage <- guard$usage()

  expect_s3_class(guard, "shieldr_rate_guard")
  expect_equal(usage$tokens_used, 10)
  expect_equal(usage$requests_made, 1)
  expect_true(rate_guard(guard))
})

test_that("rate_guard errors when a limit is exceeded", {
  guard <- rate_guard(max_tokens = 1)
  guard$update(tokens = 10, cost_usd = 0)

  expect_error(rate_guard(guard), "LLM10")
})

test_that("rate_guard resets expired windows", {
  guard <- rate_guard(max_tokens = 1, window_seconds = 1)
  guard$update(tokens = 10, cost_usd = 0)
  guard$.window_start <- Sys.time() - 2

  expect_true(rate_guard(guard))
  expect_equal(guard$usage()$tokens_used, 0)
})
