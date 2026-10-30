# Contributing to manar-edge

Thanks for helping. This project is Apache-2.0 licensed and takes contributions under the
Developer Certificate of Origin (DCO). There is no CLA.

## Sign your commits (DCO)

Every commit must carry a `Signed-off-by:` line that matches the commit author:

```bash
git commit -s -m "fix(scope): short lowercase subject"
```

By signing off you certify the [Developer Certificate of Origin 1.1](https://developercertificate.org/):
that you wrote the change or have the right to submit it under this project's licence. A GitHub
Action (`.github/workflows/dco.yml`) fails a pull request if any commit in it lacks the line.
To fix a PR: `git rebase --signoff origin/main` and force-push your branch.

## Set up and run the tests

Needs Go 1.x toolchain (see `go.mod`).

```bash
go vet ./...
go test -race ./...
CGO_ENABLED=0 go build -trimpath -o bin/ ./cmd/...
# optional, needs root and network namespaces:
sudo -E go test -tags jail ./...
```

Run these before you open a pull request. A change that touches behaviour needs a test that
fails without it.

## Pull request rules

- Fork, branch from `main`, and open the pull request against `main`. Keep it to one purpose.
- Conventional commits, lowercase subject, body lines at most 100 characters
  (`feat(scope): ...`, `fix(scope): ...`, `docs: ...`).
- Say in the description what changed, how you tested it and what you chose where the issue left
  room.
- No secrets, tokens, customer data or personal data in code, tests, fixtures or logs. Use
  placeholders such as `example.com` and `00000000-0000-0000-0000-000000000000`.
- Fail closed: an error on an authorization, identity or tenant decision denies.
- Keep claims honest. Do not write "guaranteed", "tamper-proof", "unhackable", "immutable" or
  "production-ready". Prefer "tamper-evident", "enforced", "verifiable".
- New dependencies need a sentence on why the standard library or an existing dependency does
  not cover it.
- Some files in this repository mention a private workspace (`../docs/...`). Ignore those
  pointers; this README and `CONTRIBUTING.md` are enough to build and test.

## Reporting security issues

Do not use issues or pull requests. See [SECURITY.md](SECURITY.md).

## Conduct

By taking part you agree to the [Code of Conduct](CODE_OF_CONDUCT.md). The Manar name and logo
are covered by [TRADEMARK.md](TRADEMARK.md).
