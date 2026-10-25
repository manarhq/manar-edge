# manar-edge: rules for contributors and coding agents

- `docs/design.md` is the contract with manar-api, manar-web and manar-infra. Code that disagrees
  with it is a bug in one of the two; change both in the same MR round.
- Go standard library first. A new dependency needs a line in the MR saying why the standard
  library or an existing dependency does not cover it.
- No secrets in the repo, in logs or in error messages. Keys and certificates are written 0600
  (Linux) or SYSTEM/Administrators-only (Windows) and never printed.
- Fail closed: an error on a decision path (hook, proxy allow check, peer sync) denies.
- Conventional commits, lowercase subject, body lines at most 100 characters. No AI attribution in
  commits or MRs. Never push to `main`.
- No em or en dashes in user-facing text. Do not write "guaranteed", "tamper-proof",
  "unhackable", "immutable" or "production-ready".
