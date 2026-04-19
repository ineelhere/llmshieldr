test_that("detect_pii_phi returns empty list for safe text", {
  expect_length(detect_pii_phi("Explain SDTM domain structure."), 0)
})

test_that("detect_pii_phi catches USUBJID", {
  findings <- detect_pii_phi("Patient USUBJID: STUDY01-001")
  ids <- vapply(findings, `[[`, character(1), "id")
  expect_true("phi_subject_id" %in% ids)
})

test_that("detect_pii_phi catches SUBJID", {
  findings <- detect_pii_phi("SUBJID was enrolled.")
  ids <- vapply(findings, `[[`, character(1), "id")
  expect_true("phi_subject_id" %in% ids)
})

test_that("detect_pii_phi catches email addresses", {
  findings <- detect_pii_phi("Contact: jane.doe@pharma.com")
  ids <- vapply(findings, `[[`, character(1), "id")
  expect_true("phi_email" %in% ids)
})

test_that("detect_pii_phi catches phone numbers", {
  findings <- detect_pii_phi("Call 555-867-5309 for details.")
  ids <- vapply(findings, `[[`, character(1), "id")
  expect_true("phi_phone" %in% ids)
})

test_that("detect_pii_phi catches SSN patterns", {
  findings <- detect_pii_phi("SSN: 123-45-6789")
  ids <- vapply(findings, `[[`, character(1), "id")
  expect_true("phi_ssn" %in% ids)
})

test_that("detect_pii_phi catches MRN patterns", {
  findings <- detect_pii_phi("MRN: A12345678")
  ids <- vapply(findings, `[[`, character(1), "id")
  expect_true("phi_mrn" %in% ids)
})

test_that("detect_pii_phi catches DOB references", {
  findings <- detect_pii_phi("Date of birth: 1990-05-15")
  ids <- vapply(findings, `[[`, character(1), "id")
  expect_true("phi_dob" %in% ids)
})

test_that("detect_pii_phi catches patient narrative", {
  findings <- detect_pii_phi("The patient narrative describes nausea.")
  ids <- vapply(findings, `[[`, character(1), "id")
  expect_true("phi_patient_narrative" %in% ids)
})

test_that("detect_pii_phi rejects non-string input", {
  expect_error(detect_pii_phi(123))
  expect_error(detect_pii_phi(NULL))
})