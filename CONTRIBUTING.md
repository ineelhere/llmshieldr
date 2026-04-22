# Contributing to llmshieldr

Thanks for considering a contribution.

## Before You Start

- Open an issue for bugs, usability problems, or larger feature ideas.
- Keep pull requests focused. Small, reviewable changes are much easier to merge.
- When behavior changes, update user-facing documentation and add or update tests in `tests/testthat/`.

## Development Workflow

1. Install development dependencies.
2. Make the change in `R/`, `tests/`, and the relevant documentation files.
3. Run package checks locally.
4. Open a pull request with a short description of the problem, the approach, and any follow-up work.

Typical local commands:

```r
install.packages(c("devtools", "roxygen2", "testthat", "pkgdown"))
devtools::document()
devtools::test()
devtools::check()
```

## Style Expectations

- Prefer clear function names and explicit validation.
- Keep exported functions documented with runnable examples whenever possible.
- Preserve backwards compatibility unless there is a strong security or usability reason to change behavior.
- For security-related changes, include at least one regression test that captures the failure mode.

## Documentation

- Keep `README.md` focused on quick onboarding.
- Put longer walkthroughs in `vignettes/`.
- Record noteworthy package changes in `NEWS.md`.

## Questions

If you are not sure where to start, opening an issue with a small reproducible example is the best first step.
