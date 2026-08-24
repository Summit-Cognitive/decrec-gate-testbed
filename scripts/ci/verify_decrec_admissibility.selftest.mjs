#!/usr/bin/env node
// Prove the admissibility gate can refuse, and prove it actually looked, before
// trusting it to admit.
//
// This file exists because of two defects found in our own systems:
//
//   1. A policy check that reports PASS when its input is absent is
//      indistinguishable from no check at all. Every fail-open shape below must
//      be exercised, every run.
//
//   2. An earlier version of this self-test asserted exit codes and nothing
//      else. An eight-line lookup table with no network code passed it 6 of 6.
//      So every admitting case now also asserts that the checker made a ledger
//      request AND a receipt request. A gate that returns the right integers
//      without talking to a ledger fails here.
//
// Node builtins only. No network beyond a local stub. No install.

import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const CHECKER = join(HERE, "verify_decrec_admissibility.mjs");

const REPO = "Summit-Cognitive/summit";
const POLICY = "c4e991f3b6269061f5cc02e423c16ac96cc24cab21e916b4351227efebdbd8ed";
const OTHER_POLICY = "cdfa5b1af0000000000000000000000000000000000000000000000000000000";
const SHA = (n) => String(n).repeat(40).slice(0, 40);

const NINE = ["minimum_source_count", "source_type_diversity", "provenance_required",
  "minimum_confidence", "required_evidence_admitted", "decision_rights_satisfied",
  "deterministic_replay", "human_approval", "risk_scope_bounded"];
const passing = () => NINE.map((name) => ({ name, status: "PASS", detail: "ok" }));

const entry = (seq, pr, sha, adm, id) => ({
  ts: "2026-08-22T00:00:00.000Z", receipt_id: id, chain_sequence: seq,
  claim_id: `gh-Summit-Cognitive-summit-pr-${pr}-${sha.slice(0, 7)}`,
  repository: REPO, pull_request: pr, admissibility: adm,
});

const body = (pr, commit, over = {}) => ({
  receipt: {
    subject: { repository: REPO, pull_request: pr, commit },
    policy: { status: "PASS", version: "policy-v1.0", checks: passing() },
    admissibility: { status: "ACCEPTED", reasons: [] },
    evidence: { policy_hash: POLICY },
    ...over,
  },
});
// deep-ish override helper for nested blocks
const withSubject = (b, s) => ({ receipt: { ...b.receipt, subject: { ...b.receipt.subject, ...s } } });
const dropKey = (b, k) => { const r = { ...b.receipt }; delete r[k]; return { receipt: r }; };

// pr number -> [ledger entries], receipt id -> body
const LEDGER = [], RECEIPTS = {};
const add = (seq, pr, sha, admListing, doc) => {
  const id = `r-${pr}`;
  LEDGER.push(entry(seq, pr, sha, admListing, id));
  RECEIPTS[id] = doc;
};

add(101, 101, SHA(1), "ACCEPTED", body(101, SHA(1)));
add(102, 102, SHA(2), "POLICY_FAILURE", { receipt: { ...body(102, SHA(2)).receipt,
  policy: { status: "FAIL", version: "policy-v1.0", checks: [...passing().slice(1),
    { name: "minimum_source_count", status: "FAIL", detail: "Source count 1; required 2" }] },
  admissibility: { status: "POLICY_FAILURE", reasons: ["Source count 1; required 2"] } } });
// receipt bound to a different commit than the head we will ask about
add(103, 103, SHA(3), "ACCEPTED", withSubject(body(103, SHA(3)), { commit: SHA(9) }));
// listing says ACCEPTED, signed body says POLICY_FAILURE. The body must win.
add(104, 104, SHA(4), "ACCEPTED", { receipt: { ...body(104, SHA(4)).receipt,
  admissibility: { status: "POLICY_FAILURE", reasons: ["stub"] } } });
// no admissibility block at all: must fail, must NOT fall back to the listing
add(105, 105, SHA(5), "ACCEPTED", dropKey(body(105, SHA(5)), "admissibility"));
// withheld body, the exact shape four live receipts return today
add(106, 106, SHA(6), "ACCEPTED", { receipt: { withheld: true, reason: "receipt body contains operator identity" } });
// empty object as the receipt document
add(107, 107, SHA(7), "ACCEPTED", { receipt: {} });
// null receipt wrapper
add(108, 108, SHA(8), "ACCEPTED", { receipt: null });
// wrong repository in the signed body
add(109, 109, SHA(1).replace(/^1/, "a"), "ACCEPTED", withSubject(body(109, SHA(1).replace(/^1/, "a")), { repository: "attacker/evil" }));
// evaluated under the other policy that also calls itself policy-v1.0
add(110, 110, SHA(2).replace(/^2/, "b"), "ACCEPTED", { receipt: { ...body(110, SHA(2).replace(/^2/, "b")).receipt,
  evidence: { policy_hash: OTHER_POLICY } } });
// policy PASS overall but one named check did not pass
add(111, 111, SHA(3).replace(/^3/, "c"), "ACCEPTED", { receipt: { ...body(111, SHA(3).replace(/^3/, "c")).receipt,
  policy: { status: "PASS", version: "policy-v1.0",
    checks: passing().map(c => c.name === "human_approval" ? { ...c, status: "SKIP", detail: "absent" } : c) } } });
// two receipts for one claim, split across a page boundary, newest is a refusal
const SPLIT_SHA = SHA(4).replace(/^4/, "d");
add(2, 112, SPLIT_SHA, "ACCEPTED", body(112, SPLIT_SHA));
LEDGER.push(entry(400, 112, SPLIT_SHA, "POLICY_FAILURE", "r-112-late"));
RECEIPTS["r-112-late"] = { receipt: { ...body(112, SPLIT_SHA).receipt,
  policy: { status: "FAIL", version: "policy-v1.0", checks: passing() },
  admissibility: { status: "POLICY_FAILURE", reasons: ["later refusal"] } } };
// zero checks: must refuse, not admit with "checks=0/0 PASS"
add(114, 114, SHA(6).replace(/^6/, "f"), "ACCEPTED", { receipt: { ...body(114, SHA(6).replace(/^6/, "f")).receipt,
  policy: { status: "PASS", version: "policy-v1.0", checks: [] } } });
// a partial check set: eight of nine
add(115, 115, SHA(7).replace(/^7/, "0"), "ACCEPTED", { receipt: { ...body(115, SHA(7).replace(/^7/, "0")).receipt,
  policy: { status: "PASS", version: "policy-v1.0", checks: passing().slice(0, 8) } } });
// an unexpected check name alongside the nine
add(116, 116, SHA(8).replace(/^8/, "1"), "ACCEPTED", { receipt: { ...body(116, SHA(8).replace(/^8/, "1")).receipt,
  policy: { status: "PASS", version: "policy-v1.0", checks: [...passing(), { name: "always_true", status: "PASS", detail: "" }] } } });
// listing entry with no ts at all: must not be able to sort itself to the front
LEDGER.push({ ...entry(1, 113, SHA(5).replace(/^5/, "e"), "ACCEPTED", "r-113"), ts: undefined });
RECEIPTS["r-113"] = body(113, SHA(5).replace(/^5/, "e"));
const REFUSED_113 = entry(401, 113, SHA(5).replace(/^5/, "e"), "POLICY_FAILURE", "r-113-late");
LEDGER.push(REFUSED_113);
RECEIPTS["r-113-late"] = { receipt: { ...body(113, SHA(5).replace(/^5/, "e")).receipt,
  policy: { status: "FAIL", version: "policy-v1.0", checks: passing() },
  admissibility: { status: "POLICY_FAILURE", reasons: ["later refusal"] } } };

LEDGER.sort((a, b) => a.chain_sequence - b.chain_sequence);

// The stub paginates the way production does: entries within a page ascend by
// chain_sequence, pages walk backwards, next_before is the lowest sequence
// returned. Small pages so the split-claim case really straddles a boundary.
let ledgerHits = 0, receiptHits = 0;
const PAGE = 4;
const server = createServer((req, res) => {
  const url = new URL(req.url, "http://x");
  res.setHeader("content-type", "application/json");
  if (url.pathname === "/v1/ledger") {
    ledgerHits++;
    const before = url.searchParams.get("before");
    const pool = LEDGER.filter(e => before == null || e.chain_sequence < Number(before));
    const page = pool.slice(-PAGE);
    return res.end(JSON.stringify({
      entries: page, count: page.length, total: LEDGER.length,
      next_before: page.length ? page[0].chain_sequence : null,
    }));
  }
  const m = url.pathname.match(/^\/v1\/receipts\/(.+)$/);
  if (m) {
    const id = decodeURIComponent(m[1]);
    if (RECEIPTS[id]) { receiptHits++; return res.end(JSON.stringify(RECEIPTS[id])); }
  }
  res.statusCode = 404;
  res.end(JSON.stringify({ error: "not found" }));
});

const run = (env) => new Promise((resolve) => {
  const p = spawn(process.execPath, [CHECKER], {
    env: { ...process.env, GITHUB_REPOSITORY: REPO, DECREC_MAX_PAGES: "60",
      DECREC_POLICY_HASHES: POLICY, DECREC_REPO_ALIASES: "BrianCLong/summit", ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let out = "";
  p.stdout.on("data", d => (out += d));
  p.stderr.on("data", d => (out += d));
  p.on("close", code => resolve({ code, out }));
});

const results = [];
function check(label, want, got, extra) {
  let ok = got.code === want.code;
  let why = ok ? "" : `exit ${got.code}, expected ${want.code}`;
  if (ok && want.says && !got.out.includes(want.says)) { ok = false; why = `output did not mention ${JSON.stringify(want.says)}`; }
  if (ok && extra) { const e = extra(); if (e) { ok = false; why = e; } }
  results.push(ok);
  console.log(`  [${ok ? "PASS" : "FAIL"}] ${label.padEnd(58)} ${ok ? `exit ${got.code}` : why}`);
}

server.listen(0, async () => {
  const BASE = `http://127.0.0.1:${server.address().port}`;
  const E = (pr, sha) => ({ DECREC_BASE: BASE, PR_NUMBER: String(pr), HEAD_SHA: sha });
  console.log("decrec-gate self-test");
  console.log("=".repeat(78));

  // 1. the happy path, and it must actually have talked to the ledger
  {
    const l0 = ledgerHits, r0 = receiptHits;
    const got = await run(E(101, SHA(1)));
    check("admitted receipt passes, and the gate really looked", { code: 0, says: "ADMITTED" }, got,
      () => (ledgerHits > l0 && receiptHits > r0) ? null
        : `no ledger/receipt request was made (ledger +${ledgerHits - l0}, receipt +${receiptHits - r0})`);
  }

  check("refused receipt fails", { code: 1, says: "REFUSED" }, await run(E(102, SHA(2))));
  check("receipt bound to another commit fails", { code: 1, says: "different commit" }, await run(E(103, SHA(3))));
  check("signed body beats an ACCEPTED listing", { code: 1, says: "REFUSED" }, await run(E(104, SHA(4))));
  check("no admissibility block fails, no listing fallback", { code: 2, says: "admissibility block" }, await run(E(105, SHA(5))));
  check("withheld body fails closed", { code: 2, says: "withheld" }, await run(E(106, SHA(6))));
  check("empty receipt object fails closed", { code: 2 }, await run(E(107, SHA(7))));
  check("null receipt fails closed", { code: 2 }, await run(E(108, SHA(8))));
  check("wrong repository in the signed body is refused", { code: 1, says: "attacker/evil" }, await run(E(109, SHA(1).replace(/^1/, "a"))));
  check("unpinned policy hash is refused", { code: 1, says: "policy" }, await run(E(110, SHA(2).replace(/^2/, "b"))));
  check("a named check that did not PASS is refused", { code: 1, says: "named checks" }, await run(E(111, SHA(3).replace(/^3/, "c"))));
  check("later refusal across a page boundary wins", { code: 1, says: "REFUSED" }, await run(E(112, SHA(4).replace(/^4/, "d"))));
  check("a missing ts cannot sort a stale accept to the front", { code: 1, says: "REFUSED" }, await run(E(113, SHA(5).replace(/^5/, "e"))));

  {
    // absence, after a walk that genuinely reached the start of the chain
    const got = await run(E(999, SHA(1)));
    check("zero policy checks is refused, not admitted", { code: 1, says: "pinned policy check set" }, await run(E(114, SHA(6).replace(/^6/, "f"))));
  check("a partial check set is refused", { code: 1, says: "missing" }, await run(E(115, SHA(7).replace(/^7/, "0"))));
  check("an unexpected check name is refused", { code: 1, says: "unexpected" }, await run(E(116, SHA(8).replace(/^8/, "1"))));
  check("the admit line names the ledger it used", { code: 0, says: "decrec-gate: ledger" }, await run(E(101, SHA(1))));

  check("no receipt at all fails, absence does not pass", { code: 1, says: "no decision receipt" }, got);
  }
  {
    // absence, where the walk ran out of pages: operational, not a verdict
    const got = await run({ ...E(999, SHA(1)), DECREC_MAX_PAGES: "1" });
    check("window exhaustion is an error, not a refusal", { code: 2, says: "operational" }, got);
  }

  check("unreachable ledger fails closed", { code: 2 }, await run(E(101, SHA(1)) && { DECREC_BASE: "http://127.0.0.1:1", PR_NUMBER: "101", HEAD_SHA: SHA(1) }));
  check("missing environment fails closed", { code: 2 }, await run({ DECREC_BASE: BASE, PR_NUMBER: "", HEAD_SHA: "" }));
  check("a short sha is rejected", { code: 2 }, await run({ DECREC_BASE: BASE, PR_NUMBER: "101", HEAD_SHA: "1111111" }));
  check("an unpinned ledger host is refused", { code: 2, says: "not an allowed ledger" },
    await run({ DECREC_BASE: "https://evil.example.com", PR_NUMBER: "101", HEAD_SHA: SHA(1) }));
  check("a non-integer page limit fails closed", { code: 2 },
    await run({ ...E(101, SHA(1)), DECREC_MAX_PAGES: "x" }));

  server.close();
  console.log("=".repeat(78));
  const failed = results.filter(r => !r).length;
  if (failed) {
    console.error(`SELF-TEST FAILED: ${failed} of ${results.length}. Do not rely on this gate.`);
    process.exit(1);
  }
  console.log(`SELF-TEST PASSED ${results.length}/${results.length}. The gate distinguishes admit, refuse and error,`);
  console.log(`and it fails closed on every malformed, withheld and absent shape tested above.`);
});
