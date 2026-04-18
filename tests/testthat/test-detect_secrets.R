test_that("detect_secrets works", {
  expect_equal(length(detect_secrets("safe text")), 0)
  # Add more tests
})