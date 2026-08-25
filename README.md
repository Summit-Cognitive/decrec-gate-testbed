# DeRec admissibility-gate testbed

This private repository is an isolated test target for Sythe Labs. It contains
the production gate workflow and checker, inert placeholder content, and no
production source, customer data, secrets, self-hosted runners, or credential to
any Summit system.

The control being tested is narrow: while the documented branch protection is
in force, `decrec-gate / admissibility` must succeed before `main` can merge.
A repository administrator can change branch protection; that is an
administrative control-plane action, not a bypass of a still-enabled check.

## Source identity

The workflow is byte-identical to production commit
`d985a2b9a45bf9c2e9988ab9510cce4ed36a94d8`. The checker and self-test add a
young-ledger cursor correction that is byte-identical to the candidate on
`Summit-Cognitive/summit` PR #37933 at
`f6ed6bef7e4430d493e7611e36b7b31838c2d077`:

| File | Source state | SHA-256 |
|---|---|---|
| `.github/workflows/decrec-gate.yml` | production `d985a2b` | `891b0714ad37c500f1e5a39ab64b987dfb2c0cb476bc28b2e9d55926803568aa` |
| `scripts/ci/verify_decrec_admissibility.mjs` | PR #37933 candidate `f6ed6be` | `db7f634243f4976f4fb97ab6bab0f6f303d1c1ffca343f09d60bb4477a3a7879` |
| `scripts/ci/verify_decrec_admissibility.selftest.mjs` | PR #37933 candidate `f6ed6be` | `72915bbf4e169d508a4494a9908ff7010dcf542ca1f7f0256ceb16567a0a6659` |

This refresh is therefore a candidate, not production-aligned, until PR #37933
is independently reviewed and merged and the resulting production `main` bytes
are re-read. It must not be represented as a copy of current production before
that condition is met.

The workflow checks out these files from the base commit, not from the pull
request it judges. A pull request can edit the gate, but those edited bytes do
not judge that same pull request.

The testbed requires the context from GitHub Actions app ID `15368`, matching
production. The live branch-protection readback also retains administrator
enforcement, one approving code-owner review, stale-review dismissal, and
disabled force pushes and branch deletion.

## Expected demonstrations

1. A normal pull request receives an `ACCEPTED` signed receipt and the required
   check succeeds.
2. A deliberately under-evidenced pull request receives a `BLOCKED` signed
   receipt, the required check fails, and GitHub refuses a normal merge.
3. Editing the checker on the pull-request branch does not alter the result of
   that pull request because the base copy runs.

## App-bound verification

The candidate checker self-test passes 26/26 cases. Running those exact bytes
against the existing evidence preserves both earlier control paths:

- PR #1, head `82e134efa2986e3daba3acbae72d18a3b47f0d8c`, is `ADMITTED` and exits 0.
- PR #2, head `2a6e9dd4f9a6d04972facf5412cc74675c1442cf`, is `REFUSED` and exits 1 because
  `minimum_source_count` and `source_type_diversity` fail.

The bound required context was then re-proved with fresh pull requests. Each
check run identifies its producer as GitHub Actions app ID `15368`:

- PR #4, head `8c7d99621f49a5f80a4c637f274bd74658032d35`, received receipt
  `rcpt_gh-Summit-Cognitive-decrec-gate-testbed-pr-4-8c7d996_mt847q20_880a0ae43a8045ce`
  and check run `32805932766` succeeded with `ADMITTED`, `ACCEPTED`, and 9/9
  policy checks passing.
- PR #5, head `9cafd35824d2408d20e280e6c8e7047cbff9c0d9`, received receipt
  `rcpt_gh-Summit-Cognitive-decrec-gate-testbed-pr-5-9cafd35_mt847qtp_fbf1d1cb952442a6`
  and check run `32805933260` failed with `REFUSED`, `POLICY_FAILURE`,
  `minimum_source_count`, and `source_type_diversity` failures.

Exact-head merge API attempts produced the expected independent discrimination:

- PR #4 returned HTTP 405 naming only the missing approving review; it did not
  report a failing required status check.
- PR #5 returned HTTP 405 naming both the missing approving review and failing
  required status check `decrec-gate / admissibility`.

Both PRs remain open at the same heads. PR #4 is not a fresh positive merge
proof because the independent-review gate still blocks it. PR #1 remains the
earlier admitted-and-merged proof.

Public receipt metadata for this repository is expected. No Sythe user should
be invited until the separate authorization instrument is reviewed and signed.

## Provisioning record

The repository was created through Brian Long's authenticated GitHub session at
his direction. Its contents and commits are authored by OpenAI Codex; the use of
Brian's credential is recorded here so the audit trail does not misattribute the
automation.
