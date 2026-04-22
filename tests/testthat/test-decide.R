test_that("decide_action returns correct actions with default thresholds", {
  expect_equal(decide_action(0, NULL), "allow")
  expect_equal(decide_action(19, NULL), "allow")
  expect_equal(decide_action(20, NULL), "warn")
  expect_equal(decide_action(49, NULL), "warn")
  expect_equal(decide_action(50, NULL), "redact")
  expect_equal(decide_action(99, NULL), "redact")
  expect_equal(decide_action(100, NULL), "block")
  expect_equal(decide_action(500, NULL), "block")
})

test_that("decide_action respects policy thresholds", {
  strict_policy <- list(
    name = "strict",
    thresholds = list(block = 80, redact = 40, warn = 10)
  )
  expect_equal(decide_action(5, strict_policy), "allow")
  expect_equal(decide_action(15, strict_policy), "warn")
  expect_equal(decide_action(50, strict_policy), "redact")
  expect_equal(decide_action(80, strict_policy), "block")
})

test_that("decide_action respects rule-level escalation", {
  strict_policy <- list(
    name = "strict",
    thresholds = list(block = 80, redact = 40, warn = 10)
  )

  expect_equal(
    decide_action(10, strict_policy, findings = list(list(action = "block"))),
    "block"
  )
  expect_equal(
    decide_action(10, strict_policy, findings = list(list(action = "redact"))),
    "redact"
  )
})

test_that("decide_action rejects non-numeric score", {
  expect_error(decide_action("high", NULL))
  expect_error(decide_action(c(10, 20), NULL))
})
