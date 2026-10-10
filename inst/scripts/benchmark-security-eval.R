# Lightweight local benchmark for the packaged starter corpus.
#
# This script is intentionally opt-in. It is useful before releases, but it is
# not run automatically by package examples or vignettes.

library(llmshieldr)

results <- evaluate_security_cases(policy = "comprehensive")

summary <- summarize_security_evaluation(results)
summary$package_version <- as.character(utils::packageVersion("llmshieldr"))
summary$r_version <- paste(R.version$major, R.version$minor, sep = ".")

print(summary)
print(summarize_security_evaluation(results, by = "category"))
print(results)
