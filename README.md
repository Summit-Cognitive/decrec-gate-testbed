# DeRec admissibility-gate testbed

This private repository is an isolated test target for Sythe Labs. It contains
the production gate workflow and checker, inert placeholder content, and no
production source, customer data, secrets, self-hosted runners, or credential to
any Summit system.

The control being tested is narrow: while the documented branch protection is
in force, `decrec-gate / admissibility` must succeed before `main` can merge.
A repository administrator can change branch protection; that is an
administrative control-plane action, not a bypass of a still-enabled check.

## Production-source identity

The three gate files were copied from `Summit-Cognitive/summit` commit
`d985a2b9a45bf9c2e9988ab9510cce4ed36a94d8`:

| File | SHA-256 |
|---|---|
| `.github/workflows/decrec-gate.yml` | `891b0714ad37c500f1e5a39ab64b987dfb2c0cb476bc28b2e9d55926803568aa` |
| `scripts/ci/verify_decrec_admissibility.mjs` | `2a3e9ab50e7e4d3ba2959e0a69b735f2f01346a603e8c39cfe09b97dcadf08a8` |
| `scripts/ci/verify_decrec_admissibility.selftest.mjs` | `e22343a3475828aa985ee2cac5e34a1a4284f84dd24f6738cb4cc0949dcc0a27` |

The workflow checks out these files from the base commit, not from the pull
request it judges. A pull request can edit the gate, but those edited bytes do
not judge that same pull request.

The testbed currently requires the context by name with no GitHub App binding.
Production binds the same context to GitHub Actions app ID `15368`. Before any
external reviewer receives access, an administrator must apply that same app
binding here and re-prove both the admitted and refused paths.

## Expected demonstrations

1. A normal pull request receives an `ACCEPTED` signed receipt and the required
   check succeeds.
2. A deliberately under-evidenced pull request receives a `BLOCKED` signed
   receipt, the required check fails, and GitHub refuses a normal merge.
3. Editing the checker on the pull-request branch does not alter the result of
   that pull request because the base copy runs.

## Refresh verification

The production-aligned checker self-test passes 26/26 cases. Running that exact
checker against the existing testbed evidence produces both control paths:

- PR #1, head `82e134efa2986e3daba3acbae72d18a3b47f0d8c`, is `ADMITTED` and exits 0.
- PR #2, head `2a6e9dd4f9a6d04972facf5412cc74675c1442cf`, is `REFUSED` and exits 1 because
  `minimum_source_count` and `source_type_diversity` fail.

This proves the refreshed checker preserves the earlier verdicts. It does not
replace the required new two-path proof after the GitHub App binding is applied.

Public receipt metadata for this repository is expected. No Sythe user should
be invited until the separate authorization instrument is reviewed and signed.

## Provisioning record

The repository was created through Brian Long's authenticated GitHub session at
his direction. Its contents and commits are authored by OpenAI Codex; the use of
Brian's credential is recorded here so the audit trail does not misattribute the
automation.
