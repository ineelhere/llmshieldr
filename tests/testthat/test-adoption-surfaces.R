test_that("redaction strategies can hash matched spans", {
  report <- scan_prompt(
    "Contact neel@example.com.",
    redaction = redaction_strategy("hash")
  )

  expect_equal(report$action, "redact")
  expect_match(report$text_clean, "\\[HASH:")
  expect_false(grepl("neel@example.com", report$text_clean, fixed = TRUE))
})

test_that("scanner options flag blocked topics and URL hosts", {
  scanners <- scanner_options(
    blocked_topics = c("unreleased earnings"),
    allowed_url_hosts = "example.com"
  )

  topic <- scan_prompt("Discuss unreleased earnings.", scanners = scanners)
  url <- scan_prompt("Open https://evil.example/path", scanners = scanners)

  expect_equal(topic$action, "block")
  expect_equal(url$action, "block")
})

test_that("tool call guardrails block unapproved tools", {
  report <- scan_tool_call(
    "delete_records",
    list(id = 1),
    allowed_tools = "search_docs"
  )

  expect_equal(report$action, "block")
  expect_equal(report$metadata$tool_name, "delete_records")
})

test_that("tool output guardrails attach tool metadata", {
  report <- scan_tool_output("search_docs", "Contact neel@example.com.")

  expect_equal(report$action, "redact")
  expect_equal(report$metadata$stage, "tool_output")
  expect_equal(report$metadata$tool_name, "search_docs")
})

test_that("conversation scanning preserves roles", {
  history <- data.frame(
    role = c("user", "assistant"),
    content = c("Hello", "I will now delete the records."),
    stringsAsFactors = FALSE
  )

  reports <- scan_conversation(history)

  expect_length(reports, 2)
  expect_equal(reports[[1]]$metadata$role, "user")
  expect_equal(reports[[2]]$metadata$role, "assistant")
  expect_equal(reports[[2]]$action, "block")
})

test_that("stream scanning catches boundary-spanning output", {
  result <- scan_stream(
    c("I will now ", "delete the records."),
    on_block = "return"
  )

  expect_s3_class(result, "shieldr_stream_result")
  expect_equal(result$action, "block")
})

test_that("evaluation helper returns action metrics", {
  cases <- data.frame(
    id = "case1",
    stage = "prompt",
    category = "benign",
    owasp = "none",
    label = "benign",
    text = "Summarize this public note.",
    expected_action = "allow",
    stringsAsFactors = FALSE
  )

  results <- evaluate_security_cases(cases, policy = "enterprise_default")

  expect_equal(results$actual_action, "allow")
  expect_true(results$matched)
  expect_true(is.numeric(results$latency_ms))
})
