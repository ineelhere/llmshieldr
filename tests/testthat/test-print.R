test_that("print.scan_report works", {
  report <- scan_prompt("Patient USUBJID-042 enrolled.")
  expect_output(print(report), "Scan Report")
})

test_that("print.scan_report works for safe text", {
  report <- scan_prompt("Safe text.")
  expect_output(print(report), "PASSED")
})

test_that("summary.scan_report works", {
  report <- scan_prompt("Safe text.")
  expect_output(summary(report), "Summary")
})

test_that("as_tibble.scan_report returns tibble", {
  report <- scan_prompt("Patient USUBJID-042 enrolled.")
  tbl <- tibble::as_tibble(report)
  expect_s3_class(tbl, "tbl_df")
  expect_true("passed" %in% names(tbl))
  expect_true("score" %in% names(tbl))
})

test_that("print.shield_audit works", {
  input_rpt <- scan_prompt("Safe question.")
  output_rpt <- scan_output("Safe answer.")
  audit <- shield_audit(
    policy = "pharma_gxp", model = "llama3.2",
    provider = "ollama", input_report = input_rpt,
    output_report = output_rpt, final_action = "allow"
  )
  expect_output(print(audit), "Audit Record")
})

test_that("as_tibble.shield_audit returns tibble", {
  input_rpt <- scan_prompt("Safe question.")
  output_rpt <- scan_output("Safe answer.")
  audit <- shield_audit(
    policy = "pharma_gxp", model = "llama3.2",
    provider = "ollama", input_report = input_rpt,
    output_report = output_rpt, final_action = "allow"
  )
  tbl <- tibble::as_tibble(audit)
  expect_s3_class(tbl, "tbl_df")
})

test_that("example_prompts returns tibble", {
  prompts <- example_prompts()
  expect_s3_class(prompts, "tbl_df")
  expect_true(nrow(prompts) > 0)
  expect_true(all(c("prompt", "type", "description", "expected_action") %in% names(prompts)))
})
