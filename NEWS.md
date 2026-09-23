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
- Extended `secure_chat()` to accept every provider supported by
  `ellmer::chat()`, including provider-specific arguments and separate
  assistant and reviewer provider/model selection. Assistant chats are created
  only after prompt and context checks pass, so blocked requests do not probe
  or initialize their provider.
- Deprecated `shield_ollama()` and `shield_gemini()` in favor of the common
  `secure_chat(provider = ...)` path. Both compatibility wrappers continue to
  work and now issue R's standard deprecation warning.
- Added tool policies with argument schemas, subject authorization, custom
  destination validators, spend limits, and per-run call/side-effect budgets,
  plus a provider-neutral `guard_tool()` dispatcher.
- Added context provenance/tenant/ACL/freshness admission, destination-specific
  output contracts, citation grounding checks, canonical URL destination
  policy, document-ingestion provenance, checksum-aware entity recognizers,
  and a versioned secret signature registry.
- Added a narrow optional detector-provider protocol and opt-in Presidio,
  Gitleaks, and Open Policy Agent adapters without adding Python, services, or
  binaries to core installation requirements.
- Added reviewer timeout/retry controls and an escalation failure outcome.
  Rate guards can reserve maximum output tokens, limit wall time and tool
  calls, or delegate atomic accounting to a shared backend.
- Added policy versions/fingerprints, decision IDs, structured audit metrics,
  privacy-safe telemetry callbacks, policy diff tooling, confidence intervals
  for evaluation summaries, and an exported OWASP 2026 migration crosswalk.
- Added opt-in `show_stats` messages to every exported function, including
  scanning, guarded chat, and HTTP reviewer workflows. Transfer rates are
  reported where body bytes and request duration are measurable.
- Fixed UTF-8 evaluation-corpus loading and Unicode confusable normalization
  on non-UTF-8 Windows locales.

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
