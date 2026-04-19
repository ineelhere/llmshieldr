test_that("redact_text returns unchanged text with no findings", {
  result <- redact_text("Safe text.", list())
  expect_equal(result$text, "Safe text.")
  expect_length(result$redaction_log, 0)
})

test_that("redact_text replaces matched patterns", {
  findings <- detect_pii_phi("Contact: jane.doe@pharma.com")
  result <- redact_text("Contact: jane.doe@pharma.com", findings)
  expect_true(grepl("REDACTED_EMAIL", result$text))
  expect_false(grepl("jane.doe@pharma.com", result$text))
})

test_that("redact_text returns a redaction log", {
  findings <- detect_pii_phi("Contact: jane.doe@pharma.com")
  result <- redact_text("Contact: jane.doe@pharma.com", findings)
  expect_true(length(result$redaction_log) >= 1)
  expect_true("rule_id" %in% names(result$redaction_log[[1]]))
  expect_true("original_match" %in% names(result$redaction_log[[1]]))
  expect_true("mask" %in% names(result$redaction_log[[1]]))
})

test_that("redact_text handles multiple findings", {
  text <- "Email: a@b.com, USUBJID detected."
  findings <- detect_pii_phi(text)
  result <- redact_text(text, findings)
  expect_true(grepl("REDACTED", result$text))
})

test_that("redact_text rejects non-string input", {
  expect_error(redact_text(123, list()))
})
