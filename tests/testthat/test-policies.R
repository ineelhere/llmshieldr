test_that("policy_preset returns pharma_gxp", {
  policy <- policy_preset("pharma_gxp")
  expect_equal(policy$name, "pharma_gxp")
  expect_true(length(policy$rules) > 0)
  expect_true(is.list(policy$thresholds))
  expect_true(all(c("block", "redact", "warn") %in% names(policy$thresholds)))
})

test_that("policy_preset returns enterprise_default", {
  policy <- policy_preset("enterprise_default")
  expect_equal(policy$name, "enterprise_default")
  expect_true(length(policy$rules) > 0)
})

test_that("policy_preset returns finance_guard", {
  policy <- policy_preset("finance_guard")
  expect_equal(policy$name, "finance_guard")
  expect_true(length(policy$rules) > 0)
})

test_that("policy_preset returns legal_guard", {
  policy <- policy_preset("legal_guard")
  expect_equal(policy$name, "legal_guard")
  expect_true(length(policy$rules) > 0)
})

test_that("policy_preset filters rules by policy tag", {
  policy <- policy_preset("pharma_gxp")
  for (rule in policy$rules) {
    expect_true("pharma_gxp" %in% rule$policy_tags)
  }
})

test_that("pharma_gxp has stricter thresholds than enterprise_default", {
  pharma <- policy_preset("pharma_gxp")
  enterprise <- policy_preset("enterprise_default")
  expect_true(pharma$thresholds$block <= enterprise$thresholds$block)
})

test_that("policy_preset errors on unknown name", {
  expect_error(policy_preset("nonexistent"))
})

test_that("policy_preset rejects non-string input", {
  expect_error(policy_preset(123))
})
