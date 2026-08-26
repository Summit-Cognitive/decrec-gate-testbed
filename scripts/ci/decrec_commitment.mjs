// decrec_commitment.mjs — recompute a decision receipt's commitment hash.
//
// Ported from the published offline verifier summit-verify.py v1.2.0 and
// VALIDATED byte-exact against live production receipts (blocked 5fa8e6a1…,
// accepted a51be389…, genesis 112ae548…) and each receipt's own stated ledger
// hash. See GATE_HARDENING_VALIDATION.md. Node builtins only, no install.
//
// The gate imports this to turn "the ledger said ACCEPTED" into "a receipt whose
// signature verifies, over a hash recomputed from its own body, said ACCEPTED".
// The self-test imports the SAME module to sign its stub receipts, so the check
// exercised in test is the check that runs in production.

import { createHash } from "node:crypto";

const MERKLE = "summit-decrec-merkle-v1";

// Canonical JSON (JCS / RFC 8785). In JS, String(number) IS the RFC 8785 number
// form and Object.keys().sort() IS UTF-16 code-unit order, so the port is small.
export function jcs(v) {
  if (v === null) return "null";
  const t = typeof v;
  if (t === "boolean") return v ? "true" : "false";
  if (t === "number") {
    if (!Number.isFinite(v)) throw new Error("non-finite number is not valid JCS");
    return Object.is(v, -0) ? "0" : String(v);
  }
  if (t === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(jcs).join(",") + "]";
  if (t === "object") {
    const ks = Object.keys(v).sort();
    return "{" + ks.map((k) => JSON.stringify(k) + ":" + jcs(v[k])).join(",") + "}";
  }
  throw new Error("jcs: unsupported type " + t);
}

function sha(...parts) {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return h.digest("hex");
}

// summit-decrec-merkle-v1: domain-separated leaves (0x00), pairwise nodes (0x01)
// with ODD-PROMOTION not duplication (CVE-2012-2459 guard), root (0x02) binds the
// scheme id and the leaf count.
function flattenLeaves(v, path = []) {
  if (Array.isArray(v)) {
    if (v.length === 0) return [[path, "empty-array", null]];
    let out = [];
    v.forEach((e, i) => { out = out.concat(flattenLeaves(e, path.concat([i]))); });
    return out;
  }
  if (v !== null && typeof v === "object") {
    const ks = Object.keys(v).sort();
    if (ks.length === 0) return [[path, "empty-object", null]];
    let out = [];
    for (const k of ks) out = out.concat(flattenLeaves(v[k], path.concat([k])));
    return out;
  }
  return [[path, "primitive", v]];
}
function hashLeaf(l) { return sha(Buffer.from([0]), Buffer.from(jcs([l[0], l[1], l[2]]), "utf8")); }
function foldToRoot(digests) {
  if (digests.length === 0) return sha(Buffer.from([1]));
  let level = digests;
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 === level.length) next.push(level[i]);
      else next.push(sha(Buffer.from([1]), Buffer.from(level[i], "hex"), Buffer.from(level[i + 1], "hex")));
    }
    level = next;
  }
  return level[0];
}
function merkleRoot(v) {
  const leaves = flattenLeaves(v);
  const tree = foldToRoot(leaves.map(hashLeaf));
  return sha(Buffer.from([2]), Buffer.from(jcs([MERKLE, leaves.length]), "utf8"), Buffer.from(tree, "hex"));
}

// attestations and chain are stripped — that is the signed-core contract.
export function receiptCore(receipt) {
  const out = {};
  for (const k of Object.keys(receipt)) if (k !== "attestations" && k !== "chain") out[k] = receipt[k];
  return out;
}

// Dispatch on the receipt's OWN declared scheme; an unknown scheme fails loud.
export function commitmentHash(receipt) {
  const core = receiptCore(receipt);
  const cm = core.commitment;
  const scheme = (cm && typeof cm === "object") ? cm.scheme : undefined;
  if (scheme === MERKLE) return merkleRoot(core);
  if (typeof scheme === "string") throw new Error("unsupported commitment scheme: " + scheme);
  return sha(Buffer.from(jcs(core), "utf8"));
}
