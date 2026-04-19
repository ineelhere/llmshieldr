test_that("score_findings returns 0 for empty list", {
  expect_equal(score_findings(list()), 0)
})

test_that("score_findings sums severity correctly", {
  findings <- list(
    list(severity = 30),
    list(severity = 50),
    list(severity = 20)
  )
  expect_equal(score_findings(findings), 100)
})

test_that("score_findings works with single finding", {
  findings <- list(list(severity = 75))
  expect_equal(score_findings(findings), 75)
})

test_that("get_band returns correct bands", {
  expect_equal(get_band(0), "low")
  expect_equal(get_band(19), "low")
  expect_equal(get_band(20), "moderate")
  expect_equal(get_band(49), "moderate")
  expect_equal(get_band(50), "high")
  expect_equal(get_band(99), "high")
  expect_equal(get_band(100), "critical")
  expect_equal(get_band(500), "critical")
})

test_that("get_band rejects non-numeric input", {
  expect_error(get_band("high"))
  expect_error(get_band(c(10, 20)))
})
