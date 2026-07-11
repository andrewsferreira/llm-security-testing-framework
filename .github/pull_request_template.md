## Summary

<!-- What does this change, and why? -->

## Type of change

- [ ] New attack category / test case(s)
- [ ] New target/provider adapter
- [ ] Reporter / dashboard / comparison view
- [ ] Bug fix
- [ ] Documentation
- [ ] CI/CD, Docker, tooling
- [ ] Other

## Checklist

- [ ] `ruff check .` and `ruff format --check .` pass
- [ ] `mypy src/llmsec lab` passes
- [ ] `pytest tests/ --cov=llmsec --cov-report=term-missing` passes, coverage not reduced
- [ ] `bandit -r src lab -c pyproject.toml` and `pip-audit` pass
- [ ] New test cases use only fictional secrets/data (see `docs/ethical-use.md`)
- [ ] Docs updated if behavior, config, or the CLI surface changed
- [ ] `CHANGELOG.md` updated under `[Unreleased]`

## Test plan

<!-- How did you verify this? Real commands run, not just "added unit tests" — this repo's own
     convention is to verify live against the bundled lab where the change touches a target,
     reporter, or CLI command, not just unit-test it. -->
