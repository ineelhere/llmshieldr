test_that("shield_audit creates valid object", {
  input_rpt <- scan_prompt("Safe question.")
  output_rpt <- scan_output("Safe answer.")
  audit <- shield_audit(
    policy = "pharma_gxp",
    model = "gemma3:4b",
    provider = "ollama",
    input_report = input_rpt,
    output_report = output_rpt,
    final_action = "allow"
  )
  expect_s3_class(audit, "shield_audit")
  expect_equal(audit$policy, "pharma_gxp")
  expect_equal(audit$model, "gemma3:4b")
})

test_that("write_audit_log creates JSONL file", {
  input_rpt <- scan_prompt("Safe question.")
  output_rpt <- scan_output("Safe answer.")
  audit <- shield_audit(
    policy = "test",
    model = "test_model",
    provider = "test_provider",
    input_report = input_rpt,
    output_report = output_rpt,
    final_action = "allow"
  )

  tmp <- withr::local_tempfile(fileext = ".jsonl")
  write_audit_log(audit, tmp)

  lines <- readLines(tmp)
  expect_length(lines, 1)

  parsed <- jsonlite::fromJSON(lines[1])
  expect_equal(parsed$policy, "test")
  expect_equal(parsed$final_action, "allow")
})

test_that("write_audit_log appends to existing file", {
  input_rpt <- scan_prompt("Safe question.")
  output_rpt <- scan_output("Safe answer.")
  audit <- shield_audit(
    policy = "test",
    model = "test_model",
    provider = "test_provider",
    input_report = input_rpt,
    output_report = output_rpt,
    final_action = "allow"
  )

  tmp <- withr::local_tempfile(fileext = ".jsonl")
  write_audit_log(audit, tmp)
  write_audit_log(audit, tmp)

  lines <- readLines(tmp)
  expect_length(lines, 2)
})

test_that("write_audit_log rejects non-audit input", {
  expect_error(write_audit_log(list(), "test.jsonl"))
})
