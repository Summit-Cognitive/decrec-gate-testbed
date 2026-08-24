#!/usr/bin/env node
// Decision-receipt admissibility gate.
//
// Fails the check unless a decision receipt for THIS head commit exists, binds to
// this commit, this pull request and this repository, was produced under a pinned
// policy, and was ACCEPTED with every named check passing.
//
// Fail-closed on every ambiguity. Absence must not pass, and neither must a
// missing field: every binding check below is REQUIRED, never conditional on the
// field being present. A check that skips when its input is absent is the defect
// this gate exists to prevent, and an earlier draft of this file contained
// eleven of them.
//
// The verdict is read from the SIGNED RECEIPT BODY only, never from the ledger
// listing. The listing is a rendered view that normalises fields (it rewrites
// `repository` on every row and redacts `agent` on some), so it is not the
// record and must not decide a merge.
//
// Node builtins only. No install.
//
// Env:
//   GITHUB_REPOSITORY      owner/repo                     (provided by Actions)
//   PR_NUMBER              pull request number, empty on merge_group
//   HEAD_SHA               full head commit sha
//   DECREC_BASE            pinned by the workflow; only https to the allowed host
//   DECREC_MAX_PAGES       default 40
//   DECREC_POLICY_HASHES   comma-separated allowlist; empty means do not check
//   DECREC_REPO_ALIASES    comma-separated historical repository names to accept
//
// Exit codes: 0 admitted, 1 refused, 2 operational failure.

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

// The base must be pinned. An attacker who can set this env var can stand up an
// always-accept ledger; refusing anything but the allowed host over https makes
// that a workflow edit rather than an environment poke.
// Loopback is permitted so the self-test can drive a local stub. That is not a
// hole: the workflow pins DECREC_BASE, the runner is ephemeral, and the gate no
// longer executes any code supplied by the pull request, so reaching loopback
// requires already running code on the runner. If this gate is ever moved back
// to a persistent self-hosted runner, delete the loopback branch first.
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

// The ledger silently ignores unknown query parameters, so ?claim_id=N and
// ?pull_request=N do NOT filter: the response comes back as if the parameter were
// absent. Filtering must happen client side or the gate would read somebody
// else's verdict. Do not "optimise" this into a server-side filter until the
// endpoint rejects unknown parameters with 400, and prove it does before relying
// on it. Confirmed at startup below.
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
  // Do NOT stop at the first page containing a hit. Entries within a page are
  // ascending by chain_sequence while pages walk backwards, so a claim whose
  // receipts straddle a page boundary would otherwise be decided by page
  // geometry rather than by the chain.
  return { found, pagesWalked, exhausted };
}

// The claim id convention has already changed once inside this ledger's
// lifetime, from gh-BrianCLong-summit-pr-N-sha7 to gh-Summit-Cognitive-summit-...
// Match on the pull request and commit prefix rather than reconstructing the
// whole string from the current repository name.
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
  // Prove the ledger honours (or at least does not silently mangle) what we ask
  // it, once, before trusting a page walk. If two different pages come back
  // identical the pagination is not working and a "no receipt" result would be
  // meaningless.
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
    // Distinguish "searched the whole chain and it is not there" from "ran out of
    // pages". The second is an operational failure, not a policy refusal, and
    // saying otherwise turns a red gate into an instruction to mint a receipt.
    if (!exhausted) {
      die(2, `decrec-gate: no receipt for ${DESCRIBE} in the ${pagesWalked * 200} most recent ledger entries,\n` +
             `  and the walk did not reach the start of the chain. This is an operational\n` +
             `  limit, not a verdict. Raise DECREC_MAX_PAGES or add a server-side filter.`);
    }
    refuse(`no decision receipt anywhere in the chain for ${DESCRIBE}`,
           `A pull request with no receipt is not admissible.`);
  }

  // Most recent verdict wins, ordered by chain_sequence. The chain binds the
  // sequence; it does not bind `ts`, which the minter supplies and which is
  // absent or malformed on a receipt an attacker controls.
  found.sort((a, b) => a.chain_sequence - b.chain_sequence);
  const e = found[found.length - 1];

  let doc;
  try { doc = await getJson(`${BASE}/v1/receipts/${encodeURIComponent(e.receipt_id)}`); }
  catch (err) { die(2, `decrec-gate: receipt ${e.receipt_id} unreadable (${err.message}). Failing closed.`); }
  if (!doc || doc.__notfound) die(2, `decrec-gate: receipt ${e.receipt_id} returned 404. Failing closed.`);

  const receipt = doc.receipt || doc;
  if (!receipt || typeof receipt !== "object") die(2, `decrec-gate: receipt ${e.receipt_id} is not an object. Failing closed.`);
  if (receipt.withheld) die(2, `decrec-gate: receipt ${e.receipt_id} body is withheld and cannot be verified. Failing closed.`);

  // Every one of these is REQUIRED. A missing field fails; it does not skip.
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
  // An empty or partial check list must not admit. `checks.filter(non-PASS)` over
  // an empty array is empty, so without this a receipt carrying zero checks
  // reaches the admit path with "checks=0/0 PASS". Pin the set by name.
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

  console.log(`decrec-gate: ledger     ${BASE}`);
  console.log(`decrec-gate: claim      ${e.claim_id}`);
  console.log(`decrec-gate: receipt    ${e.receipt_id}`);
  console.log(`decrec-gate: sequence   ${e.chain_sequence}`);
  console.log(`decrec-gate: policy     ${policy.status}  ${policy.version || "?"}  ${policyHash || "?"}`);
  console.log(`decrec-gate: checks     ${checks.length}`);

  // Allowlist, not denylist. `!== "PASS"` refuses an unknown status; `=== "FAIL"`
  // would admit one.
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
