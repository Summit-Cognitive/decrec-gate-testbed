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
`4454a72d8089f80b99bcb0c38e06015048496717`:

| File | SHA-256 |
|---|---|
| `.github/workflows/decrec-gate.yml` | `891b0714ad37c500f1e5a39ab64b987dfb2c0cb476bc28b2e9d55926803568aa` |
| `scripts/ci/verify_decrec_admissibility.mjs` | `43eaca47964636a29945d9a8b625d606451fe6d562d70baea6cce772a88e6416` |
| `scripts/ci/verify_decrec_admissibility.selftest.mjs` | `773379ae0c384d02e61d7044d7721136bb850a73994b10f91ba366e6535bcd0d` |

The workflow checks out these files from the base commit, not from the pull
request it judges. A pull request can edit the gate, but those edited bytes do
not judge that same pull request.

## Expected demonstrations

1. A normal pull request receives an `ACCEPTED` signed receipt and the required
   check succeeds.
2. A deliberately under-evidenced pull request receives a `BLOCKED` signed
   receipt, the required check fails, and GitHub refuses a normal merge.
3. Editing the checker on the pull-request branch does not alter the result of
   that pull request because the base copy runs.

Public receipt metadata for this repository is expected. No Sythe user should
be invited until the separate authorization instrument is reviewed and signed.

## Provisioning record

The repository was created through Brian Long's authenticated GitHub session at
his direction. Its contents and commits are authored by OpenAI Codex; the use of
Brian's credential is recorded here so the audit trail does not misattribute the
automation.
