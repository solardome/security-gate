# Contributing

Thanks for contributing to `security-gate`.

## Development Setup

```bash
go test ./...
GOTOOLCHAIN=go1.25.4 go test -race ./...
./scripts/simulate.sh
```

## Contribution Rules

- Keep behavior deterministic.
- Do not introduce network calls.
- Treat all input files as untrusted.
- Keep canonical contracts aligned with:
  - `docs/md/core-decision-engine.md`
  - `docs/md/policy-format.md`

## Pull Request Checklist

- [ ] Behavior changes include tests.
- [ ] `go test ./...` passes.
- [ ] `GOTOOLCHAIN=go1.25.4 go test -race ./...` passes.
- [ ] `./scripts/simulate.sh` passes.
- [ ] Docs updated when contracts change.

## Commit Messages

Use clear, scoped commit messages, for example:

- `fix(scoring): apply freshness SLA to trust penalty`
- `docs(readme): add end-to-end quickstart`
