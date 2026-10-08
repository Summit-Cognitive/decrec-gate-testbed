# DeRec admissibility-gate testbed

This public repository is an isolated, credential-free test target for Sythe
Labs. It contains the production gate workflow and checker, inert placeholder
content, and no production source, customer data, secrets, self-hosted runners,
or credential to any Summit system.

The control being tested is narrow: while the documented branch protection is
in force, `decrec-gate / admissibility` must succeed before `main` can merge.
A repository administrator can change branch protection; that is an
administrative control-plane action, not a bypass of a still-enabled check.

An unauthenticated reviewer can inspect the matched pair directly: [PR #1]
was admitted by the required check and merged, while [PR #2] was refused by
the same check and remains open with GitHub reporting it as blocked.

[PR #1]: https://github.com/Summit-Cognitive/decrec-gate-testbed/pull/1
[PR #2]: https://github.com/Summit-Cognitive/decrec-gate-testbed/pull/2

## Production-source identity

These gate files began as an exact copy of the `Summit-Cognitive/summit` gate at
commit `4454a72d8089f80b99bcb0c38e06015048496717` (the commit that first made
`decrec-gate / admissibility` a required merge gate) and now carry the 2026-08
**signature-hardening** revision described under "Signature hardening" below.

| File | SHA-256 |
|---|---|
| `.github/workflows/decrec-gate.yml` | `891b0714ad37c500f1e5a39ab64b987dfb2c0cb476bc28b2e9d55926803568aa` |
| `scripts/ci/verify_decrec_admissibility.mjs` | `33fae60ec1122894d2a9358cf3bb38e21c63b8fb31450d02e43021c5a8c5dbb1` |
| `scripts/ci/verify_decrec_admissibility.selftest.mjs` | `a15069733cec7c6aa85ed25312186bd0e744bf9bc45353dd1b5c3fae3acfa03b` |
| `scripts/ci/decrec_commitment.mjs` | `26f538647e672708d0b211bcbd05a24f332be51fd3b1bd750655ec49bc0492a0` |
| `scripts/ci/decrec-signing-key.pub.pem` | `2c946b80aaf4153c560aa9c394be5f148703730464caa53de5abbadbdc906844` |

The workflow (`decrec-gate.yml`) is unchanged from the production commit above. The
checker and self-test carry the signature hardening, and two files are added: the
shared commitment module and the pinned public key.

The workflow checks out these files from the base commit, not from the pull
request it judges. A pull request can edit the gate, but those edited bytes do
not judge that same pull request.

### Relationship to current production

Summit's production checker has moved one commit past `4454a72d`: commit
`d985a2b9` (#37929, 2026-08-25) adds a bounded poll for asynchronously-minted
receipts so the required gate cannot jam the merge queue. That change is
CI-robustness only — it does not alter any binding, verdict, or fail-closed
behaviour (when the poll budget expires the gate still refuses). The signature
hardening shown here is being applied to Summit's current production checker in
parallel; the two then differ only by that merge-queue poll, and the
signature-verification behaviour a reviewer inspects here is identical to
production's.

### Signature hardening (2026-08)

Before this revision the gate read the ACCEPTED/BLOCKED verdict from the signed
receipt body but trusted the ledger host to have served an authentic body. The
hardened checker recomputes the receipt commitment from the receipt's own body
and verifies its Ed25519 signature against a key pinned in this protected base
tree (`decrec-signing-key.pub.pem`) before honouring any verdict — failing closed
if there is no attestation, if the signature does not verify, or if the signing
key is not pinned. This answers the review objection that "the signature validity
is purely based on trust." The self-test proves the refusals (tampered body,
unpinned key, missing attestation) on every run, from the base tree, before the
checker is trusted to pass.

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
