test_that("preflight_check returns scan_report", {
  report <- preflight_check("Safe text.")
  expect_s3_class(report, "scan_report")
  expect_true(report$passed)
})

test_that("add_rule adds a valid custom rule", {
  rule <- list(
    id = "test_custom_rule", type = "phi", pattern = "TESTID-\\d+",
    severity = 25, action = "warn", mask = "[REDACTED_TESTID]",
    description = "Test custom rule", owasp = "LLM02",
    policy_tags = c("enterprise_default")
  )
  add_rule(rule)
  custom <- list_rules(custom_only = TRUE)
  ids <- vapply(custom, `[[`, character(1), "id")
  expect_true("test_custom_rule" %in% ids)

  # Clean up
  remove_rule("test_custom_rule")
})

test_that("add_rule rejects duplicate IDs", {
  rule <- list(
    id = "test_dup_rule", type = "phi", pattern = "X",
    severity = 10, action = "warn", mask = "[X]",
    description = "Dup test", owasp = "LLM02",
    policy_tags = c("enterprise_default")
  )
  add_rule(rule)
  expect_error(add_rule(rule))
  remove_rule("test_dup_rule")
})

test_that("add_rule rejects incomplete rules", {
  expect_error(add_rule(list(id = "incomplete")))
})

test_that("remove_rule removes custom rules", {
  rule <- list(
    id = "test_remove_rule", type = "phi", pattern = "Y",
    severity = 10, action = "warn", mask = "[Y]",
    description = "Remove test", owasp = "LLM02",
    policy_tags = c("enterprise_default")
  )
  add_rule(rule)
  remove_rule("test_remove_rule")
  custom <- list_rules(custom_only = TRUE)
  ids <- if (length(custom) > 0) vapply(custom, `[[`, character(1), "id") else character(0)
  expect_false("test_remove_rule" %in% ids)
})

test_that("remove_rule cannot remove built-in rules", {
  expect_error(remove_rule("secret_openai_key"))
})

test_that("list_rules returns all rules", {
  rules <- list_rules()
  expect_true(length(rules) > 0)
})

test_that("list_rules custom_only returns only custom", {
  custom <- list_rules(custom_only = TRUE)
  # Should be empty unless previous tests leaked
  expect_type(custom, "list")
})

test_that("explain_findings returns character vector", {
  report <- scan_prompt("Patient USUBJID-042, email: test@clinic.org")
  explanations <- explain_findings(report$findings)
  expect_type(explanations, "character")
  expect_true(length(explanations) > 0)
})

test_that("explain_findings returns empty vector for no findings", {
  expect_length(explain_findings(list()), 0)
})
