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
# llmshieldr (development version)

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
  preserving existing rule IDs.
- Added Gemini Developer API workflow examples and `shield_gemini()`, alongside
  the Ollama path.
- Added opt-in `show_stats` messages to scanning and guarded chat workflows.
- Fixed Unicode confusable normalization on non-UTF-8 Windows locales.
