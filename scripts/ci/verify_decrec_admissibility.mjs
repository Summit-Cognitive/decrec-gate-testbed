#!/usr/bin/env node
// Decision-receipt admissibility gate.
//
// Fails the check unless a decision receipt for THIS head commit exists, binds to
// this commit, this pull request and this repository, was produced under a pinned
// policy, was ACCEPTED with every named check passing, AND carries an Ed25519
// signature that VERIFIES — over a commitment recomputed from the receipt's own
// body — under a key pinned in this protected base tree.
//
// The signature check is the 2026-08 hardening. Before it, the gate read the
// verdict from the signed body but trusted the ledger host to have served an
// authentic body. Now the merge rests on cryptography a pull request cannot
// forge: a receipt whose signature does not verify under a pinned key is REFUSED,
// where before it would have been admitted. (Answers the reviewer objection:
// "the signature validity is purely based on trust.")
//
// Fail-closed on every ambiguity. Absence must not pass, and neither must a
// missing field: every binding check below is REQUIRED, never conditional on the
// field being present.
//
// The verdict is read from the SIGNED RECEIPT BODY only, never from the ledger
// listing. Node builtins only. No install.
//
// Env:
//   GITHUB_REPOSITORY      owner/repo                     (provided by Actions)
//   PR_NUMBER              pull request number, empty on merge_group
//   HEAD_SHA               full head commit sha
//   DECREC_BASE            pinned by the workflow; only https to the allowed host
//   DECREC_MAX_PAGES       default 40
//   DECREC_POLICY_HASHES   comma-separated allowlist; empty means do not check
//   DECREC_REPO_ALIASES    comma-separated historical repository names to accept
//   DECREC_TEST_PUBKEY     test-only signing pubkey, honoured ONLY vs a loopback ledger
//
// Exit codes: 0 admitted, 1 refused, 2 operational failure.

import { readFileSync } from "node:fs";
import { createHash, createPublicKey, verify as edVerify } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { commitmentHash } from "./decrec_commitment.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));

const ALLOWED_HOSTS = new Set(["decrec.summitcognitive.ai"]);

const RAW_BASE = process.env.DECREC_BASE || "https://decrec.summitcognitive.ai";
const MAX_PAGES = Number(process.env.DECREC_MAX_PAGES || 40);
const REPO = process.env.GITHUB_REPOSITORY || "";
const PR = process.env.PR_NUMBER || "";
const HEAD_SHA = process.env.HEAD_SHA || "";
const POLICY_HASHES = new Set((process.env.DECREC_POLICY_HASHES || "").split(",").map(s => s.trim()).filter(Boolean));
const REPO_ALIASES = (process.env.DECREC_REPO_ALIASES || "BrianCLong/summit").split(",").map(s => s.trim()).filter(Boolean);

// The nine named checks the disclosure claims are evaluated. Pinned by name so a
// receipt with fewer checks, or different ones, cannot admit by having nothing
// that failed.
const REQUIRED_CHECKS = (process.env.DECREC_REQUIRED_CHECKS ||
  "minimum_source_count,source_type_diversity,provenance_required,minimum_confidence," +
  "required_evidence_admitted,decision_rights_satisfied,deterministic_replay,human_approval," +
  "risk_scope_bounded").split(",").map(s => s.trim()).filter(Boolean);

const die = (code, msg) => { console.error(msg); process.exit(code); };
const refuse = (...lines) => die(1, ["decrec-gate: REFUSED", ...lines.map(l => "  " + l)].join("\n"));

if (!REPO || !HEAD_SHA) die(2, "decrec-gate: missing GITHUB_REPOSITORY or HEAD_SHA. Failing closed.");
if (!/^[0-9a-f]{40}$/.test(HEAD_SHA)) die(2, `decrec-gate: HEAD_SHA ${JSON.stringify(HEAD_SHA)} is not a full sha. Failing closed.`);
if (!Number.isInteger(MAX_PAGES) || MAX_PAGES < 1) die(2, `decrec-gate: DECREC_MAX_PAGES ${JSON.stringify(process.env.DECREC_MAX_PAGES)} is not a positive integer. Failing closed.`);

// The base must be pinned. Loopback is permitted so the self-test can drive a
// local stub; the workflow pins DECREC_BASE and the runner is ephemeral.
const isLoopback = (h) => h === "127.0.0.1" || h === "localhost" || h === "[::1]" || h === "::1";
let BASE;
try {
  const u = new URL(RAW_BASE);
  const ok = (u.protocol === "https:" && ALLOWED_HOSTS.has(u.hostname)) || (u.protocol === "http:" && isLoopback(u.hostname));
  if (!ok) throw new Error("not an allowed ledger");
  BASE = u.origin;
} catch (e) {
  die(2, `decrec-gate: DECREC_BASE ${JSON.stringify(RAW_BASE)} is not an allowed ledger (${e.message}). Failing closed.`);
}

// --- signing keys pinned in the protected base tree ------------------------
// The gate admits only a receipt whose signature verifies under a key it pins
// here, in a tree a pull request cannot alter without a CODEOWNERS review. key_id
// is sha256 over the DER SPKI, recomputed from the key material, so a receipt's
// stated key_id is an index, never a trust input.
const keyId = (pem) => "sha256:" + createHash("sha256").update(createPublicKey(pem).export({ type: "spki", format: "der" })).digest("hex");
const PINNED = new Map();
try {
  const pem = readFileSync(join(HERE, "decrec-signing-key.pub.pem"), "utf8");
  PINNED.set(keyId(pem), pem);
} catch { /* absent only in a bare checkout; the loopback self-test injects its own key below */ }
// Test-only key, honoured ONLY against a loopback ledger — the identical trust
// envelope the self-test stub already runs inside. In production DECREC_BASE is
// pinned to the https host, so this branch cannot be reached without already
// executing code on the ephemeral runner.
if (process.env.DECREC_TEST_PUBKEY && isLoopback(new URL(RAW_BASE).hostname)) {
  try { const pem = process.env.DECREC_TEST_PUBKEY; PINNED.set(keyId(pem), pem); } catch { /* ignore a malformed test key */ }
}
if (PINNED.size === 0) die(2, "decrec-gate: no signing key is pinned; the gate cannot authenticate any receipt. Failing closed.");

const ACCEPTABLE_REPOS = new Set([REPO, ...REPO_ALIASES]);

async function getJson(url, tries = 3) {
  let last;
  for (let i = 0; i < tries; i++) {
    try {
      const res = await fetch(url, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(15000) });
      if (res.status === 404) return { __notfound: true };
      if (res.status >= 500) { last = new Error(`HTTP ${res.status}`); await new Promise(r => setTimeout(r, 500 * (i + 1))); continue; }
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    } catch (e) { last = e; if (i < tries - 1) await new Promise(r => setTimeout(r, 500 * (i + 1))); }
  }
  throw last;
}

async function findEntries(match) {
  const found = [];
  let before = null, pagesWalked = 0, exhausted = false;
  for (let page = 0; page < MAX_PAGES; page++) {
    const d = await getJson(`${BASE}/v1/ledger?limit=200${before ? `&before=${before}` : ""}`);
    const entries = Array.isArray(d.entries) ? d.entries : [];
    pagesWalked++;
    if (!entries.length) { exhausted = true; break; }
    for (const e of entries) if (match(e)) found.push(e);
    before = d.next_before;
    if (!before) { exhausted = true; break; }
  }
  return { found, pagesWalked, exhausted };
}

const sha7 = HEAD_SHA.slice(0, 7);
const claimMatches = (e) => {
  const c = String(e.claim_id || "");
  if (!c.endsWith(`-${sha7}`)) return false;
  const m = c.match(/(?:^|-)pr-(\d+)-/);
  if (!m) return false;
  return PR ? String(m[1]) === String(PR) : true;
};
const DESCRIBE = PR ? `pull request ${PR} at ${sha7}` : `commit ${sha7}`;

(async () => {
  try {
    const [p1, p2] = await Promise.all([
      getJson(`${BASE}/v1/ledger?limit=2`),
      getJson(`${BASE}/v1/ledger?limit=2&before=100`),
    ]);
    const k = (d) => (d.entries || []).map(e => e.chain_sequence).join(",");
    if (!k(p1) || k(p1) === k(p2)) die(2, "decrec-gate: the ledger did not honour pagination; a page walk cannot be trusted. Failing closed.");
  } catch (err) {
    die(2, `decrec-gate: could not reach the ledger (${err.message}). Failing closed.`);
  }

  let found, pagesWalked, exhausted;
  try { ({ found, pagesWalked, exhausted } = await findEntries(claimMatches)); }
  catch (err) { die(2, `decrec-gate: could not read the ledger (${err.message}). Failing closed.`); }

  if (!found.length) {
    if (!exhausted) {
      die(2, `decrec-gate: no receipt for ${DESCRIBE} in the ${pagesWalked * 200} most recent ledger entries,\n` +
             `  and the walk did not reach the start of the chain. This is an operational\n` +
             `  limit, not a verdict. Raise DECREC_MAX_PAGES or add a server-side filter.`);
    }
    refuse(`no decision receipt anywhere in the chain for ${DESCRIBE}`,
           `A pull request with no receipt is not admissible.`);
  }

  found.sort((a, b) => a.chain_sequence - b.chain_sequence);
  const e = found[found.length - 1];

  let doc;
  try { doc = await getJson(`${BASE}/v1/receipts/${encodeURIComponent(e.receipt_id)}`); }
  catch (err) { die(2, `decrec-gate: receipt ${e.receipt_id} unreadable (${err.message}). Failing closed.`); }
  if (!doc || doc.__notfound) die(2, `decrec-gate: receipt ${e.receipt_id} returned 404. Failing closed.`);

  const receipt = doc.receipt || doc;
  if (!receipt || typeof receipt !== "object") die(2, `decrec-gate: receipt ${e.receipt_id} is not an object. Failing closed.`);
  if (receipt.withheld) die(2, `decrec-gate: receipt ${e.receipt_id} body is withheld and cannot be verified. Failing closed.`);

  for (const k of ["subject", "policy", "admissibility"])
    if (!receipt[k] || typeof receipt[k] !== "object")
      die(2, `decrec-gate: receipt ${e.receipt_id} has no ${k} block. Failing closed.`);

  const subj = receipt.subject;
  if (!subj.commit) die(2, `decrec-gate: receipt ${e.receipt_id} names no commit. Failing closed.`);
  if (subj.commit !== HEAD_SHA)
    refuse(`receipt binds to commit ${subj.commit}`, `this head is ${HEAD_SHA}`,
           `A receipt for a different commit does not admit this one.`);
  if (PR) {
    if (subj.pull_request == null) die(2, `decrec-gate: receipt ${e.receipt_id} names no pull request. Failing closed.`);
    if (String(subj.pull_request) !== String(PR))
      refuse(`receipt names pull request ${subj.pull_request}, this is ${PR}.`);
  }
  if (!subj.repository) die(2, `decrec-gate: receipt ${e.receipt_id} names no repository. Failing closed.`);
  if (!ACCEPTABLE_REPOS.has(subj.repository))
    refuse(`receipt names repository ${subj.repository}`, `this is ${REPO}.`);

  const policy = receipt.policy;
  const adm = receipt.admissibility;
  const checks = Array.isArray(policy.checks) ? policy.checks : null;
  if (!checks) die(2, `decrec-gate: receipt ${e.receipt_id} carries no policy checks. Failing closed.`);
  const seen = new Set(checks.map(c => c && c.name));
  const missing = REQUIRED_CHECKS.filter(n => !seen.has(n));
  const unexpected = [...seen].filter(n => !REQUIRED_CHECKS.includes(n));
  if (missing.length || unexpected.length)
    refuse(`receipt does not carry the pinned policy check set`,
           missing.length ? `missing: ${missing.join(", ")}` : "",
           unexpected.length ? `unexpected: ${unexpected.join(", ")}` : "");

  const policyHash = (receipt.evidence || {}).policy_hash;
  if (POLICY_HASHES.size) {
    if (!policyHash) die(2, `decrec-gate: receipt ${e.receipt_id} declares no policy hash. Failing closed.`);
    if (!POLICY_HASHES.has(policyHash))
      refuse(`receipt was evaluated under policy ${policyHash}`,
             `which is not in the pinned allowlist.`,
             `Two different policies have shared the label policy-v1.0; the hash is what binds.`);
  }

  // --- cryptographic verification (the 2026-08 hardening) -------------------
  // Recompute the commitment from the receipt's own signed core, then verify the
  // Ed25519 signature over ascii(hex(commitment)) under a pinned key. This is
  // what turns "the ledger served ACCEPTED" into "a receipt whose signature
  // verifies said ACCEPTED". Every branch fails closed.
  const atts = Array.isArray(receipt.attestations) ? receipt.attestations : null;
  if (!atts || atts.length === 0)
    die(2, `decrec-gate: receipt ${e.receipt_id} carries no attestation; a verdict the gate cannot authenticate is not admissible. Failing closed.`);
  let commitment;
  try { commitment = commitmentHash(receipt); }
  catch (err) { die(2, `decrec-gate: could not recompute the receipt commitment (${err.message}). Failing closed.`); }
  const statedHash = (doc.ledger_entry || {}).receipt_hash;
  if (statedHash && statedHash !== commitment)
    refuse(`receipt body does not reproduce its committed hash`, `stated ${statedHash}`, `recomputed ${commitment}`);
  const att = atts[0];
  if (att.algorithm !== "ed25519")
    die(2, `decrec-gate: attestation algorithm ${JSON.stringify(att.algorithm)} is not ed25519. Failing closed.`);
  const pem = att.key_id && PINNED.get(att.key_id);
  if (!pem)
    refuse(`receipt is signed by key_id ${att.key_id}`,
           `which is not pinned in the gate's protected base tree.`,
           `The gate admits only receipts signed by a key it pins and a pull request cannot alter.`);
  let sigOk = false;
  try { sigOk = edVerify(null, Buffer.from(commitment, "ascii"), createPublicKey(pem), Buffer.from(String(att.signature || ""), "base64")); }
  catch (err) { die(2, `decrec-gate: signature verification errored (${err.message}). Failing closed.`); }
  if (!sigOk)
    refuse(`receipt signature does not verify under the pinned key ${att.key_id}`,
           `commitment ${commitment}`,
           `The gate will not admit a receipt whose signature it cannot cryptographically verify.`);

  console.log(`decrec-gate: ledger     ${BASE}`);
  console.log(`decrec-gate: claim      ${e.claim_id}`);
  console.log(`decrec-gate: receipt    ${e.receipt_id}`);
  console.log(`decrec-gate: sequence   ${e.chain_sequence}`);
  console.log(`decrec-gate: policy     ${policy.status}  ${policy.version || "?"}  ${policyHash || "?"}`);
  console.log(`decrec-gate: checks     ${checks.length}`);
  console.log(`decrec-gate: signature  VERIFIED  ${att.key_id}  over ascii(hex ${commitment.slice(0, 12)}…)`);

  const failed = checks.filter(c => c.status !== "PASS");
  const problems = [];
  if (adm.status !== "ACCEPTED") problems.push(`admissibility is ${adm.status}, not ACCEPTED`);
  if (policy.status !== "PASS") problems.push(`policy status is ${policy.status}, not PASS`);
  if (failed.length) problems.push(`${failed.length} of ${checks.length} named checks did not pass`);

  if (problems.length) {
    console.error("decrec-gate: REFUSED");
    for (const p of problems) console.error(`  ${p}`);
    for (const r of (adm.reasons || [])) console.error(`  reason: ${r}`);
    for (const c of failed) console.error(`  check ${c.name}: ${c.status} - ${c.detail}`);
    process.exit(1);
  }

  console.log(`decrec-gate: ADMITTED  admissibility=${adm.status} policy=${policy.status} checks=${checks.length}/${checks.length} PASS`);
})().catch(err => die(2, `decrec-gate: unexpected failure (${err && err.message}). Failing closed.`));
