# Lightweight local benchmark for the packaged starter corpus.
#
# This script is intentionally opt-in. It is useful before releases, but it is
# not run automatically by package examples or vignettes.

library(llmshieldr)

results <- evaluate_security_cases(policy = "comprehensive")

summary <- data.frame(
  cases = nrow(results),
  action_accuracy = mean(results$matched),
  median_latency_ms = stats::median(results$latency_ms),
  p95_latency_ms = as.numeric(stats::quantile(results$latency_ms, 0.95)),
  package_version = as.character(utils::packageVersion("llmshieldr")),
  r_version = paste(R.version$major, R.version$minor, sep = "."),
  stringsAsFactors = FALSE
)

print(summary)
print(results)
