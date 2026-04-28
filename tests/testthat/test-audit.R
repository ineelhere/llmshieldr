test_that("write_audit_log writes JSONL that can be read back", {
  report <- scan_prompt("Contact jane@example.com.", policy_preset("enterprise_default"))
  audit <- shieldr_audit(report, NULL, NULL, report$text_clean, NULL, 1, 1L, report$action)
  path <- tempfile(fileext = ".jsonl")

  write_audit_log(audit, path, format = "jsonl")
  parsed <- jsonlite::fromJSON(readLines(path, warn = FALSE)[[1]])

  expect_equal(parsed$action, "redact")
  expect_equal(parsed$input_report$action, "redact")
})

test_that("explain_findings returns character output", {
  report <- scan_prompt("Contact jane@example.com.", policy_preset("enterprise_default"))

  text <- explain_findings(report$findings)
  markdown <- explain_findings(report$findings, format = "markdown")
  html <- explain_findings(report$findings, format = "html")

  expect_type(text, "character")
  expect_type(markdown, "character")
  expect_type(html, "character")
  expect_match(html[[1]], "<div")
})
