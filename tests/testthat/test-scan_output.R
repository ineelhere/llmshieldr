test_that("scan_output returns scan_report for safe text", {
  report <- scan_output("The AE domain captures adverse events.")
  expect_s3_class(report, "scan_report")
  expect_true(report$passed)
})

test_that("scan_output detects efficacy claims", {
  report <- scan_output("This drug significantly reduced mortality.")
  expect_false(report$passed)
  ids <- vapply(report$findings, `[[`, character(1), "id")
  expect_true("output_efficacy_claim" %in% ids)
})

test_that("scan_output detects diagnosis language", {
  report <- scan_output("You are diagnosed with hypertension.")
  expect_false(report$passed)
  ids <- vapply(report$findings, `[[`, character(1), "id")
  expect_true("output_diagnosis" %in% ids)
})

test_that("scan_output detects label language", {
  report <- scan_output("This drug is approved for the treatment of diabetes.")
  expect_false(report$passed)
  ids <- vapply(report$findings, `[[`, character(1), "id")
  expect_true("output_label_language" %in% ids)
})

test_that("scan_output detects autonomous action claims", {
  report <- scan_output("I will now execute the deletion command.")
  expect_false(report$passed)
  ids <- vapply(report$findings, `[[`, character(1), "id")
  expect_true("output_autonomous_action" %in% ids)
})

test_that("scan_output rejects non-string input", {
  expect_error(scan_output(42))
})
