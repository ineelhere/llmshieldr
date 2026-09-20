# llmshieldr (development version)

- `explain_findings()` now accepts a report directly and returns text
  explanations invisibly after printing them once.
- Expanded the excessive-agency output rule to catch first-person commitments
  to side-effecting actions such as “I will go ahead and delete,” independently
  of the object name; documented its lexical limits.
- Added context source admission and per-row authorization before retrieved
  text can enter a model prompt.
- Made audits metadata-only by default; writing full content requires separate
  opt-ins. Stream results now release only cleaned text and strip report content
  by default.
- Added guarded tool callbacks for tool-enabled chats and a default-deny tool
  allowlist.
- Made semantic reviewer failures block by default, with an explicit
  `rules_only` fallback in `policy_controls()`.
- Updated built-in OWASP mapping and report metadata to the 2026 taxonomy while
  preserving existing rule IDs and category codes. Findings also carry an
  edition-qualified category ID.
- Added Gemini Developer API workflow examples and `shield_gemini()`, alongside
  the Ollama path.
- Added opt-in `show_stats` messages to every exported function, including
  scanning, guarded chat, and HTTP reviewer workflows. Transfer rates are
  reported where body bytes and request duration are measurable.
- Fixed Unicode confusable normalization on non-UTF-8 Windows locales.

# llmshieldr 0.1.0

## CRAN release

- First CRAN release of `llmshieldr`.
- Added model-agnostic scanners for prompts, model outputs, conversations,
  retrieved context, tool calls, tool outputs, and streaming chunks.
- Added built-in policies mapped to the OWASP LLM Top 10 for Large Language
  Model Applications 2025.
- Added deterministic rule checks, optional NLP intent checks, optional
  semantic reviewer checks, configurable redaction strategies, audit logs, rate
  guards, and Ollama helpers.
- Added vignettes for getting started, policy design, custom rules, RAG
  pipelines, OWASP coverage, evaluation, operations, threat modeling,
  architecture, ecosystem context, and Ollama usage.
