# llmshieldr

A pharma-first LLM security layer for R.

## Installation

```r
devtools::install_github("ineelhere/llmshieldr")
```

## Usage

```r
library(llmshieldr)
library(ellmer)

provider <- chat_openai(model = "gpt-4")

result <- secure_chat(
  prompt = "Summarize this patient narrative.",
  context = "Patient USUBJID-123 had adverse event.",
  provider = provider,
  policy = policy_preset("pharma_gxp"),
  action = "redact"
)

result$output
```

## Demos

### PHI leakage blocked

```r
# Demo 1
```

### Prompt injection caught

```r
# Demo 2
```

### Unsafe output flagged

```r
# Demo 3
```