test_that("namespace exports stay focused on the public workflow API", {
  exports <- getNamespaceExports("llmshieldr")

  expect_true(all(c(
    "shield_ollama",
    "secure_chat",
    "scan_prompt",
    "preflight_check",
    "scan_context",
    "scan_output",
    "policy_preset",
    "add_rule",
    "remove_rule",
    "list_rules",
    "llm_review",
    "shield_audit",
    "write_audit_log",
    "example_prompts",
    "explain_findings"
  ) %in% exports))

  expect_false(any(c(
    "detect_secrets",
    "detect_pii_phi",
    "detect_injection",
    "score_findings",
    "get_band",
    "decide_action",
    "redact_text",
    "rule_bank"
  ) %in% exports))
})
