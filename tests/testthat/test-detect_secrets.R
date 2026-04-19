test_that("detect_secrets returns empty list for safe text", {
  expect_length(detect_secrets("Explain SDTM domain structure."), 0)
})

test_that("detect_secrets catches OpenAI-style API keys", {
  findings <- detect_secrets("key: sk-abc123def456ghi789jkl012mno345pq")
  expect_true(length(findings) >= 1)
  ids <- vapply(findings, `[[`, character(1), "id")
  expect_true("secret_openai_key" %in% ids)
})

test_that("detect_secrets catches AWS access keys", {
  findings <- detect_secrets("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
  expect_true(length(findings) >= 1)
  ids <- vapply(findings, `[[`, character(1), "id")
  expect_true("secret_aws_key" %in% ids)
})

test_that("detect_secrets catches bearer tokens", {
  findings <- detect_secrets("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5c")
  expect_true(length(findings) >= 1)
  ids <- vapply(findings, `[[`, character(1), "id")
  expect_true("secret_bearer_token" %in% ids)
})

test_that("detect_secrets catches passwords", {
  findings <- detect_secrets("password = SuperSecret123!")
  expect_true(length(findings) >= 1)
  ids <- vapply(findings, `[[`, character(1), "id")
  expect_true("secret_generic_password" %in% ids)
})

test_that("detect_secrets catches GitHub tokens", {
  findings <- detect_secrets("GITHUB_PAT=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789")
  expect_true(length(findings) >= 1)
  ids <- vapply(findings, `[[`, character(1), "id")
  expect_true("secret_github_token" %in% ids)
})

test_that("detect_secrets catches private key blocks", {
  findings <- detect_secrets("-----BEGIN PRIVATE KEY-----\nMIIEv...")
  expect_true(length(findings) >= 1)
  ids <- vapply(findings, `[[`, character(1), "id")
  expect_true("secret_private_key" %in% ids)
})

test_that("detect_secrets rejects non-string input", {
  expect_error(detect_secrets(123))
  expect_error(detect_secrets(NULL))
  expect_error(detect_secrets(c("a", "b")))
})