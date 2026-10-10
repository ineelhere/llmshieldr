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
  expect_error(guard$reserve(tokens = 10), "LLM06:2026")
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

  expect_error(guard$reserve(tokens = 0, requests = 1), "LLM06:2026")
  expect_equal(guard$usage()$requests_made, 1)
})

test_that("rate_guard rejects non-finite and fractional accounting values", {
  expect_error(rate_guard(max_tokens = Inf), "finite")
  expect_error(rate_guard(max_requests = 1.5), "whole number")
  expect_error(rate_guard(max_tool_calls = Inf), "finite")
  expect_error(rate_guard(window_seconds = 0), "positive")

  guard <- rate_guard(max_tokens = 10, max_requests = 2)
  expect_error(guard$reserve(tokens = Inf), "finite")
  expect_error(guard$reserve(requests = 0.5), "whole number")
  expect_equal(guard$usage()$requests_made, 0)
})

test_that("concurrent rate guards share persisted counters after serialization", {
  skip_if_not_installed("filelock")
  guard <- rate_guard(max_requests = 2, concurrent = TRUE)
  withr::defer(unlink(c(guard$.lock_path, guard$.state_path), force = TRUE))
  copy <- unserialize(serialize(guard, NULL))

  guard$reserve(requests = 1)
  copy$reserve(requests = 1)

  expect_equal(guard$usage()$requests_made, 2)
  expect_equal(copy$usage()$requests_made, 2)
  expect_error(guard$reserve(requests = 1), "LLM06:2026")
})
