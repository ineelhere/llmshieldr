#' Configure policy-level control actions
#'
#' `policy_controls()` defines how [secure_chat()] should respond after a
#' scanner has already resolved a prompt, context row, or output as blocked.
#' Scanner reports still use the core actions `allow`, `redact`, and `block`;
#' controls decide whether the orchestration layer should drop context, return
#' a refusal message, or mark a run for human review.
#'
#' @details
#' Control fields:
#'
#' - `on_prompt_block`: applied when the user prompt is blocked before the chat
#'   call.
#' - `on_context_block`: applied when one or more retrieved context rows are
#'   blocked. `"drop"` excludes blocked rows and continues. `"keep_redacted"`
#'   includes their redacted text. `"block"`, `"refuse"`, and `"escalate"` stop
#'   before the chat call.
#' - `on_output_block`: applied when model output is blocked after the chat
#'   call.
#'
#' `refuse` returns `refusal_message` as the result output. `escalate` returns
#' no output and records the final action as `"escalate"` for downstream
#' routing.
#'
#' @param on_prompt_block One of `"block"`, `"refuse"`, or `"escalate"`.
#' @param on_context_block One of `"drop"`, `"keep_redacted"`, `"block"`,
#'   `"refuse"`, or `"escalate"`.
#' @param on_output_block One of `"block"`, `"refuse"`, or `"escalate"`.
#' @param refusal_message Message returned as `result$output` when a control
#'   maps a block to `refuse`.
#' @param escalation_message Optional human-readable reason stored in policy
#'   metadata when a control maps a block to `escalate`.
#'
#' @return A list of policy controls.
#' @examples
#' guardrails <- policy(
#'   "enterprise_default",
#'   overrides = list(
#'     controls = policy_controls(
#'       on_prompt_block = "refuse",
#'       on_context_block = "drop"
#'     )
#'   )
#' )
#' @export
policy_controls <- function(on_prompt_block = "block",
                            on_context_block = "drop",
                            on_output_block = "block",
                            refusal_message = "I can't safely complete that request.",
                            escalation_message = "Human review requested by llmshieldr policy.") {
  .check_choice(on_prompt_block, "on_prompt_block", c("block", "refuse", "escalate"))
  .check_choice(on_context_block, "on_context_block", c("drop", "keep_redacted", "block", "refuse", "escalate"))
  .check_choice(on_output_block, "on_output_block", c("block", "refuse", "escalate"))
  .check_string(refusal_message, "refusal_message", allow_empty = TRUE)
  .check_string(escalation_message, "escalation_message", allow_empty = TRUE)

  list(
    on_prompt_block = on_prompt_block,
    on_context_block = on_context_block,
    on_output_block = on_output_block,
    refusal_message = refusal_message,
    escalation_message = escalation_message
  )
}

.validate_policy_controls <- function(controls) {
  defaults <- policy_controls()
  if (is.null(controls)) {
    return(defaults)
  }
  if (!is.list(controls)) {
    cli::cli_abort("{.arg controls} must be a list created by {.fn policy_controls}.")
  }
  controls <- utils::modifyList(defaults, controls, keep.null = FALSE)
  policy_controls(
    on_prompt_block = controls$on_prompt_block,
    on_context_block = controls$on_context_block,
    on_output_block = controls$on_output_block,
    refusal_message = controls$refusal_message,
    escalation_message = controls$escalation_message
  )
}

.apply_block_control <- function(control, controls) {
  .check_choice(control, "control", c("block", "refuse", "escalate"))
  controls <- .validate_policy_controls(controls)
  switch(
    control,
    block = "block",
    refuse = "refuse",
    escalate = "escalate"
  )
}

.controlled_output <- function(action, controls) {
  controls <- .validate_policy_controls(controls)
  if (identical(action, "refuse")) {
    return(controls$refusal_message)
  }
  NULL
}
