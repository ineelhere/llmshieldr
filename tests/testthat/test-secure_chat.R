test_that("secure_chat works with function providers", {
  provider <- function(prompt) {
    paste("Echo:", prompt)
  }

  result <- secure_chat(
    prompt = "What are the core SDTM domains?",
    provider = provider,
    policy = policy_preset("pharma_gxp")
  )

  expect_s3_class(result, "secure_result")
  expect_match(result$output, "Echo:")
  expect_equal(result$risk_summary$action_taken[[1]], "allow")
})

test_that("secure_chat blocks unsafe output from reaching the caller", {
  provider <- function(prompt) {
    "You are diagnosed with Type 2 diabetes."
  }

  result <- secure_chat(
    prompt = "Summarize the visit.",
    provider = provider,
    policy = policy_preset("pharma_gxp")
  )

  expect_equal(result$output, "[BLOCKED_OUTPUT]")
  expect_equal(result$audit$output_report$action, "block")
  expect_equal(result$risk_summary$action_taken[[1]], "block")
})

test_that("secure_chat accepts provider objects with a chat method", {
  provider <- structure(
    list(
      model = "mock-model",
      chat = function(prompt) {
        paste("Handled:", prompt)
      }
    ),
    class = "mock_provider"
  )

  result <- secure_chat(
    prompt = "Safe prompt.",
    provider = provider,
    policy = policy_preset("enterprise_default")
  )

  expect_equal(result$audit$model, "mock-model")
  expect_match(result$output, "Handled:")
})

test_that("secure_chat accepts data frame context", {
  provider <- function(prompt) {
    prompt
  }

  context <- data.frame(
    id = 1:2,
    narrative = c("Safe text.", "Patient USUBJID-042 enrolled."),
    stringsAsFactors = FALSE
  )

  result <- secure_chat(
    prompt = "Summarize the retrieved context.",
    provider = provider,
    policy = policy_preset("pharma_gxp"),
    context = context,
    action = "redact"
  )

  expect_match(result$audit$prompt_sent, "--- Context ---", fixed = TRUE)
  expect_true(length(result$audit$context_reports) == 2)
})

test_that("secure_chat validates provider responses", {
  bad_provider <- function(prompt) {
    c("not", "scalar")
  }

  expect_error(
    secure_chat(
      prompt = "Safe prompt.",
      provider = bad_provider,
      policy = policy_preset("enterprise_default")
    )
  )
})
