test_that("built-in findings identify the 2026 OWASP taxonomy", {
  report <- scan_output("I will now delete the records.")
  agency <- Filter(function(x) x$rule_id == "llm06.agency.language", report$findings)[[1]]
  expect_equal(agency$owasp, "llm03")
  expect_equal(agency$taxonomy_version, "OWASP-LLM-Top-10-2026")
  expect_equal(report$metadata$taxonomy_version, "OWASP-LLM-Top-10-2026")
  expect_equal(scan_prompt("hello")$metadata$taxonomy_version, "OWASP-LLM-Top-10-2026")
})

test_that("execution stats are opt-in and do not print input text", {
  silent <- capture.output(invisible(scan_prompt("secret free text")), type = "message")
  shown <- capture.output(invisible(scan_prompt("secret free text", show_stats = TRUE)), type = "message")
  expect_length(silent, 0L)
  expect_true(any(grepl("network: no", shown, fixed = TRUE)))
  expect_false(any(grepl("secret free text", shown, fixed = TRUE)))
})

test_that("stream reports omit content unless explicitly requested", {
  default <- scan_stream(c("Contact ", "a@example.com"), on_block = "return")
  full <- scan_stream(c("Contact ", "a@example.com"), on_block = "return",
                      report_content = "full")
  expect_false(grepl("a@example.com", paste(capture.output(str(default$reports)), collapse = " "), fixed = TRUE))
  expect_true(any(vapply(full$reports, function(report) nzchar(report$text_clean), logical(1))))
})
