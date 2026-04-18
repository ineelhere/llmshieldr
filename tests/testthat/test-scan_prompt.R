test_that("scan_prompt works", {
  report <- scan_prompt("safe text")
  expect_s3_class(report, "scan_report")
  expect_true(report$passed)
  report2 <- scan_prompt("USUBJID-123")
  expect_false(report2$passed)
  expect_equal(report2$score, 50)
})