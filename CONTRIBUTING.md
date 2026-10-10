# Contributing to llmshieldr

Thanks for considering a contribution.

## Before You Start

- Open an issue for bugs, usability problems, or larger feature ideas.
- Keep pull requests focused. Small, reviewable changes are much easier to merge.
- When behavior changes, update user-facing documentation and add or update tests in `tests/testthat/`.

## Development Workflow

1. Install the released package from CRAN with `install.packages("llmshieldr")`
   if you want a reference version for comparison.
2. Install development dependencies.
3. Make the change in `R/`, `tests/`, and the relevant documentation files.
4. Run package checks locally.
5. Open a pull request with a short description of the problem, the approach, and any follow-up work.

Typical local commands:

```r
install.packages(c("devtools", "roxygen2", "testthat", "pkgdown"))
devtools::document()
devtools::test()
devtools::check()
```

Edit `README.Rmd` and Roxygen comments in `R/`. Do not hand-edit generated
`README.md`, `man/*.Rd`, or `NAMESPACE` files. Run `devtools::document()` and
render `README.Rmd` after changing their sources.

## Branch and Release Policy

- `dev` is the integration branch for the development package. Its version
  must use the `.9000` development suffix.
- `main` represents the latest stable release. Changes reach `main` through a
  release pull request after checks pass and the version is finalized.
- Pull requests and pushes to `dev` build pkgdown as a downloadable preview but
  never deploy it.
- The public pkgdown site deploys only when a stable GitHub release is
  published from a tag that exactly matches `v<DESCRIPTION Version>`.
- After a stable release, resume development on `dev` with a `.9000` version.

Install the current development branch with:

```r
pak::pak("ineelhere/llmshieldr@dev")
```

## Style Expectations

- Prefer clear function names and explicit validation.
- Keep exported functions documented with runnable examples whenever possible.
- Keep network requests, credentials, downloads, and optional executables out
  of evaluated examples and vignette builds.
- Preserve backwards compatibility unless there is a strong security or usability reason to change behavior.
- For security-related changes, include at least one regression test that captures the failure mode.

## Adding Or Changing Rules

Rule changes need both detection and overblocking evidence.

- Add at least one positive test where the risky text triggers the intended rule.
- Add at least one negative test where ordinary text in the same domain is allowed.
- Use a stable rule ID with an OWASP prefix when the mapping is clear.
- Keep regex rules narrow enough to preserve useful text around the finding.
- Document any known false-positive tradeoff in the test or rule description.

## Documentation

- Keep `README.md` focused on quick onboarding.
- Put longer walkthroughs in `vignettes/`.
- Update Roxygen comments in source; never edit generated `.Rd` files.
- Record user-facing changes in `NEWS.md` before a CRAN or GitHub release.

## Questions

If you are not sure where to start, opening an issue with a small reproducible example is the best first step.
