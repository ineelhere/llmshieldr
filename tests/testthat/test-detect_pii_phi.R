test_that("detect_pii_phi works", {
  expect_equal(length(detect_pii_phi("safe text")), 0)
  findings <- detect_pii_phi("USUBJID-123")
  expect_equal(length(findings), 1)
  expect_equal(findings[[1]]$id, "phi_subject_id")
})