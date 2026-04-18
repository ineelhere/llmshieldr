test_that("detect_pii_phi works", {
  expect_equal(length(detect_pii_phi("safe text")), 0)
  # Add more tests
})