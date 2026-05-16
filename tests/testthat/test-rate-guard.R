test_that("rate_guard creates and updates usage", {
  guard <- rate_guard(max_tokens = 100, max_requests = 10)
  guard$reserve(tokens = 10)
  usage <- guard$usage()

  expect_s3_class(guard, "shieldr_rate_guard")
  expect_equal(usage$tokens_used, 10)
  expect_equal(usage$requests_made, 1)
  expect_true(rate_guard(guard))
})

test_that("rate_guard errors when a limit is exceeded", {
  guard <- rate_guard(max_tokens = 1)
  expect_error(guard$reserve(tokens = 10), "LLM10")
  expect_equal(guard$usage()$tokens_used, 0)
})

test_that("rate_guard resets expired windows", {
  guard <- rate_guard(max_tokens = 100, window_seconds = 1)
  guard$update(tokens = 10)
  guard$.window_start <- Sys.time() - 2

  expect_true(rate_guard(guard))
  expect_equal(guard$usage()$tokens_used, 0)
})

test_that("rate_guard can roll back a reservation", {
  guard <- rate_guard(max_tokens = 100, max_requests = 5)
  guard$reserve(tokens = 20, requests = 1)
  guard$rollback(tokens = 20, requests = 1)

  usage <- guard$usage()
  expect_equal(usage$tokens_used, 0)
  expect_equal(usage$requests_made, 0)
})

test_that("rate_guard blocks projected request limits", {
  guard <- rate_guard(max_requests = 1)
  guard$reserve(tokens = 0, requests = 1)

  expect_error(guard$reserve(tokens = 0, requests = 1), "LLM10")
  expect_equal(guard$usage()$requests_made, 1)
})
