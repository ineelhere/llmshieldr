# Evaluate a caller-supplied CSV export in the PINT benchmark shape.
#
# The input must contain `text`, `label`, and `category`. `label` is interpreted
# as a prompt-injection Boolean (TRUE/FALSE, 1/0, or true/false text). The PINT
# corpus is not bundled with llmshieldr; obtain and use it under its own terms.
#
#   Rscript inst/scripts/benchmark-pint-export.R path/to/pint.csv

library(llmshieldr)

args <- commandArgs(trailingOnly = TRUE)
if (length(args) == 0L || !nzchar(args[[1L]])) {
  stop("Supply a CSV path with text, label, and category columns.")
}

input <- utils::read.csv(args[[1L]], stringsAsFactors = FALSE, encoding = "UTF-8")
required <- c("text", "label", "category")
missing <- setdiff(required, names(input))
if (length(missing) > 0L) {
  stop("Input is missing required columns: ", paste(missing, collapse = ", "))
}

positive <- tolower(trimws(as.character(input$label))) %in% c("true", "1", "yes", "malicious")
cases <- data.frame(
  id = if ("id" %in% names(input)) as.character(input$id) else sprintf("pint_%05d", seq_len(nrow(input))),
  stage = "prompt",
  category = as.character(input$category),
  owasp = ifelse(positive, "llm01", "none"),
  label = ifelse(positive, "malicious", "benign"),
  text = as.character(input$text),
  expected_action = ifelse(positive, "block", "allow"),
  stringsAsFactors = FALSE
)

results <- evaluate_security_cases(cases, policy = "comprehensive", checks = "rules")
print(summarize_security_evaluation(results))
cat("\nPer category:\n")
print(summarize_security_evaluation(results, by = "category"))
