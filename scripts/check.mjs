#!/usr/bin/env node
// Offline: re-verify every witnessed head's signature and every consistency proof in the chain,
// from the files in this repository alone. No network. Exit 0 if the whole chain holds.
import { readFileSync } from 'node:fs'
import { verifySth, verifyConsistency } from './lib.mjs'

const ROOT = new URL('..', import.meta.url).pathname
const TRUSTED_KEY = readFileSync(ROOT + 'witness/trusted-key.txt', 'utf8').trim()
const anchors = JSON.parse(readFileSync(ROOT + 'witness/anchors.json', 'utf8'))
const heads = readFileSync(ROOT + 'witness/heads.jsonl', 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l))
let failures = 0
const row = (ok, text) => { console.log(`${ok ? 'PASS' : 'FAIL'}  ${text}`); if (!ok) failures++ }
for (const h of heads) {
  const s = verifySth(h, TRUSTED_KEY)
  row(s.ok, `signature  size ${h.tree_size}  ${h.root_hash.slice(0, 16)}…  ${s.ok ? '' : s.reason}`)
  if (h.consistency_from !== null) {
    const prevRoot = h.consistency_from_kind === 'recorded anchor' ? anchors[String(h.consistency_from)] : heads.find((p) => p.tree_size === h.consistency_from)?.root_hash
    const c = prevRoot ? verifyConsistency({ old_size: h.consistency_from, new_size: h.tree_size, consistency_path: h.consistency_path }, prevRoot, h.root_hash) : { ok: false, reason: 'previous root not on record' }
    row(c.ok, `consistent size ${h.consistency_from} -> ${h.tree_size}  ${c.ok ? '' : c.reason}`)
  }
}
console.log(`\n${heads.length} head(s), ${failures} failure(s)`)
process.exit(failures ? 1 : 0)
