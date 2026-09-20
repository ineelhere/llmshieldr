test_that("write_audit_log writes JSONL that can be read back", {
  report <- scan_prompt("Contact neel@example.com.", policy("enterprise_default"))
  audit <- shieldr_audit(report, NULL, NULL, report$text_clean, NULL, 1, 1L, report$action)
  path <- tempfile(fileext = ".jsonl")

  write_audit_log(audit, path, format = "jsonl")
  parsed <- jsonlite::fromJSON(readLines(path, warn = FALSE)[[1]])

  expect_equal(parsed$action, "redact")
  expect_equal(parsed$input_report$action, "redact")
})

test_that("guarded audits omit raw content by default", {
  result <- secure_chat("hello", function(prompt) "Contact a@example.com")

  expect_null(result$audit$prompt_clean)
  expect_null(result$audit$output_raw)
  expect_identical(result$audit$output_report$text_clean, "")
  path <- tempfile(fileext = ".jsonl")
  write_audit_log(result$audit, path)
  stored <- paste(readLines(path, warn = FALSE), collapse = "")
  expect_false(grepl("a@example.com", stored, fixed = TRUE))
  expect_false(grepl("Contact", stored, fixed = TRUE))
})

test_that("writing full audit content requires two explicit opt-ins", {
  result <- secure_chat(
    "hello", function(prompt) "Contact a@example.com", audit_content = "full"
  )
  expect_equal(result$audit$output_raw, "Contact a@example.com")
  safe_path <- tempfile(fileext = ".jsonl")
  raw_path <- tempfile(fileext = ".jsonl")

  write_audit_log(result$audit, safe_path)
  write_audit_log(result$audit, raw_path, include_content = TRUE)

  expect_false(grepl("a@example.com", paste(readLines(safe_path), collapse = ""), fixed = TRUE))
  expect_true(grepl("a@example.com", paste(readLines(raw_path), collapse = ""), fixed = TRUE))
})

test_that("explain_findings returns character output", {
  report <- scan_prompt("Contact neel@example.com.", policy("enterprise_default"))

  text <- explain_findings(report$findings)
  markdown <- explain_findings(report$findings, format = "markdown")
  html <- explain_findings(report$findings, format = "html")

  expect_type(text, "character")
  expect_type(markdown, "character")
  expect_type(html, "character")
  expect_match(html[[1]], "<div")
})
