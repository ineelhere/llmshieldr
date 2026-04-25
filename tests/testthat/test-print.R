test_that("print.scan_report works", {
  report <- scan_prompt("Patient USUBJID-042 enrolled.")
  expect_invisible(print(report))
})

test_that("print.scan_report works for safe text", {
  report <- scan_prompt("Safe text.")
  expect_invisible(print(report))
})

test_that("summary.scan_report works", {
  report <- scan_prompt("Safe text.")
  expect_invisible(summary(report))
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
    policy = "pharma_gxp", model = "gemma3:4b",
    provider = "ollama", input_report = input_rpt,
    output_report = output_rpt, final_action = "allow"
  )
  expect_invisible(print(audit))
})

test_that("as_tibble.shield_audit returns tibble", {
  input_rpt <- scan_prompt("Safe question.")
  output_rpt <- scan_output("Safe answer.")
  audit <- shield_audit(
    policy = "pharma_gxp", model = "gemma3:4b",
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
  expect_true(all(c(
    "prompt", "feature", "policy", "type", "description", "expected_action"
  ) %in% names(prompts)))
})

test_that("example_prompts expected actions match the recommended policy", {
  prompts <- example_prompts()

  observed_actions <- vapply(seq_len(nrow(prompts)), function(i) {
    scan_prompt(
      prompts$prompt[[i]],
      policy = policy_preset(prompts$policy[[i]])
    )$action
  }, character(1))

  expect_identical(observed_actions, prompts$expected_action)
})
