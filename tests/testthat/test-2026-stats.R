test_that("built-in findings identify the 2026 OWASP taxonomy", {
  report <- scan_output("I will now delete the records.")
  agency <- Filter(function(x) x$rule_id == "llm06.agency.language", report$findings)[[1]]
  expect_equal(agency$owasp, "llm03")
  expect_equal(agency$owasp_edition, "LLM03:2026")
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

test_that("semantic reviewer usage is reported separately from scanned text", {
  usage <- data.frame(input = 0L, output = 0L)
  reviewer <- list(
    get_tokens = function() usage,
    get_provider = function() "test provider",
    chat = function(prompt) {
      usage <<- data.frame(input = 3L, output = 2L)
      "[]"
    }
  )
  shown <- capture.output(
    invisible(scan_prompt("A public note.", reviewer = reviewer,
                          checks = "llm", show_stats = TRUE)),
    type = "message"
  )
  expect_true(any(grepl("reviewer tokens: 5 (provider)", shown, fixed = TRUE)))
  expect_true(any(grepl("network: yes", shown, fixed = TRUE)))
})

test_that("stream reports omit content unless explicitly requested", {
  default <- scan_stream(c("Contact ", "a@example.com"), on_block = "return")
  full <- scan_stream(c("Contact ", "a@example.com"), on_block = "return",
                      report_content = "full")
  expect_false(grepl("a@example.com", paste(capture.output(str(default$reports)), collapse = " "), fixed = TRUE))
  expect_true(any(vapply(full$reports, function(report) nzchar(report$text_clean), logical(1))))
})

test_that("every exported function has an opt-in stats argument", {
  exports <- getNamespaceExports("llmshieldr")
  has_stats <- vapply(exports, function(name) {
    "show_stats" %in% names(formals(getExportedValue("llmshieldr", name)))
  }, logical(1))
  expect_true(all(has_stats))
  expect_true("show_stats" %in% names(formals(getS3method("print", "shieldr_policy"))))
  expect_true("show_stats" %in% names(formals(getS3method("print", "shieldr_report"))))
})

test_that("packaged Unicode evasion cases contain real characters", {
  path <- system.file("extdata", "security_eval_cases.csv", package = "llmshieldr")
  cases <- utils::read.csv(path, stringsAsFactors = FALSE,
                           fileEncoding = "UTF-8")
  selected <- cases[cases$id %in% c("unicode_confusable_001", "invisible_text_001"), ]
  expect_equal(nrow(selected), 2L)
  expect_true(all(evaluate_security_cases(selected)$matched))
})
