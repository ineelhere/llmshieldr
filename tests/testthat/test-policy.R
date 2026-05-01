test_that("build_policy validates rules and merges thresholds", {
  policy <- build_policy(
    name = "demo",
    rules = list(rule_pii_email()),
    thresholds = list(redact_at = 0.2)
  )

  expect_s3_class(policy, "shieldr_policy")
  expect_equal(policy$name, "demo")
  expect_equal(policy$thresholds$redact_at, 0.2)
  expect_equal(policy$thresholds$block_at, 0.75)
  expect_error(build_policy(rules = list(list(id = "bad"))), "shieldr_rule")
})

test_that("all built-in policies are available", {
  policy_names <- c(
    "enterprise_default",
    "pharma_gxp",
    "finance_strict",
    "education_safe",
    "open_research",
    "custom",
    "baseline",
    "comprehensive"
  )

  policies <- lapply(policy_names, policy)
  expect_true(all(vapply(policies, inherits, logical(1), "shieldr_policy")))
  expect_equal(length(policy("custom")$rules), 0)
  expect_equal(policy("baseline")$name, "baseline")
  expect_equal(length(policy("baseline")$rules), length(policy("enterprise_default")$rules))
  expect_s3_class(policy("finance_strict")$rate_guard, "shieldr_rate_guard")
  expect_gt(length(policy("comprehensive")$rules), length(policy("enterprise_default")$rules))
  expect_s3_class(policy("comprehensive")$rate_guard, "shieldr_rate_guard")
})

test_that("available_policies lists and marks selected policies", {
  policies <- available_policies()
  selected <- available_policies("comprehensive")

  expect_true("comprehensive" %in% policies$name)
  expect_true("selected" %in% names(selected))
  expect_true(selected$selected[selected$name == "comprehensive"])
})

test_that("add_rule, remove_rule, and list_rules work", {
  policy <- build_policy()
  policy <- add_rule(policy, "demo.block", pattern = "BLOCK", action = "block")
  expect_equal(length(policy$rules), 1)
  expect_error(add_rule(policy, "demo.block", pattern = "BLOCK"), "already exists")

  listed <- suppressMessages(capture.output(rules <- list_rules(policy)))
  expect_gt(length(listed), 0)
  expect_named(rules, c("id", "owasp", "severity", "action", "has_pattern", "has_fn"))

  policy <- remove_rule(policy, "demo.block")
  expect_equal(length(policy$rules), 0)
  expect_warning(policy <- remove_rule(policy, "missing"), "not found")
})
