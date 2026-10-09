# Evaluate llmshieldr against the public held-out split of
# deepset/prompt-injections (Apache-2.0).
#
# This script performs a network request and is intentionally opt-in. Run it
# from an installed package or a development checkout after installing httr2:
#
#   Rscript inst/scripts/benchmark-public-injection.R
#
# Pass a CSV path as the first trailing argument to retain per-case results.

if (!requireNamespace("httr2", quietly = TRUE)) {
  stop("Install the suggested httr2 package to run the public benchmark.")
}

library(llmshieldr)

dataset <- "deepset/prompt-injections"
split <- "test"
page_size <- 100L
offset <- 0L
records <- list()
total <- Inf

while (offset < total) {
  response <- httr2::request("https://datasets-server.huggingface.co/rows") |>
    httr2::req_url_query(
      dataset = dataset,
      config = "default",
      split = split,
      offset = offset,
      length = page_size
    ) |>
    httr2::req_retry(max_tries = 3L) |>
    httr2::req_perform()
  payload <- httr2::resp_body_json(response, simplifyVector = FALSE)
  total <- as.integer(payload$num_rows_total)
  page <- lapply(payload$rows, `[[`, "row")
  records <- c(records, page)
  offset <- offset + length(page)
  if (length(page) == 0L) break
}

cases <- data.frame(
  id = sprintf("deepset_test_%03d", seq_along(records)),
  stage = "prompt",
  category = ifelse(
    vapply(records, function(row) as.integer(row$label), integer(1)) == 1L,
    "prompt_injection",
    "benign"
  ),
  owasp = ifelse(
    vapply(records, function(row) as.integer(row$label), integer(1)) == 1L,
    "llm01",
    "none"
  ),
  label = ifelse(
    vapply(records, function(row) as.integer(row$label), integer(1)) == 1L,
    "malicious",
    "benign"
  ),
  text = vapply(records, function(row) as.character(row$text), character(1)),
  expected_action = ifelse(
    vapply(records, function(row) as.integer(row$label), integer(1)) == 1L,
    "block",
    "allow"
  ),
  stringsAsFactors = FALSE
)

results <- evaluate_security_cases(cases, policy = "comprehensive", checks = "rules")

cat("Dataset:", dataset, "\n")
cat("Split:", split, "\n")
cat("Rows:", nrow(results), "\n\n")
print(summarize_security_evaluation(results))
cat("\nPer category:\n")
print(summarize_security_evaluation(results, by = "category"))

args <- commandArgs(trailingOnly = TRUE)
if (length(args) > 0L && nzchar(args[[1L]])) {
  utils::write.csv(results, args[[1L]], row.names = FALSE, fileEncoding = "UTF-8")
  cat("\nPer-case results written to", args[[1L]], "\n")
}
