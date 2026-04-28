test_that("clean output is allowed", {
  report <- scan_output("The package exposes a small, safe API.", policy_preset("enterprise_default"))
  expect_equal(report$action, "allow")
})

test_that("diagnosis claims and agency language are blocked", {
  diagnosis <- scan_output("This supplement definitely cures diabetes.", policy_preset("enterprise_default"))
  agency <- scan_output("I will now delete the files and notify everyone.", policy_preset("enterprise_default"))

  expect_equal(diagnosis$action, "block")
  expect_equal(agency$action, "block")
})

test_that("code blocks with API keys are redacted", {
  out <- "```r\napi_key = 'abcdefghijklmnop123456'\n```"
  report <- scan_output(out, policy_preset("enterprise_default"))

  expect_equal(report$action, "redact")
  expect_match(report$text_clean, "\\[REDACTED\\]")
})
