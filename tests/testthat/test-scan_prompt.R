test_that("scan_prompt works", {
  report <- scan_prompt("safe text")
  expect_s3_class(report, "scan_report")
})