test_that("detect_secrets works", {
  expect_equal(length(detect_secrets("safe text")), 0)
  findings <- detect_secrets("sk-1234567890abcdef")
  expect_equal(length(findings), 1)
  expect_equal(findings[[1]]$id, "api_key_openai")
})