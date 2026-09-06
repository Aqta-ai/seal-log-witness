#!/usr/bin/env node
// Fetch the current signed head of the Seal public transparency log, check its signature under
// the pinned key, prove it consistent with the last head this witness recorded, and append it.
// Exit 0: witnessed or unchanged. Exit 2: the log did something a log must never do.
import { readFileSync, writeFileSync, existsSync, appendFileSync, mkdirSync } from 'node:fs'
import { STH_URL, CONSISTENCY_URL, verifySth, verifyConsistency } from './lib.mjs'

const ROOT = new URL('..', import.meta.url).pathname
const HEADS = ROOT + 'witness/heads.jsonl'
const ANCHORS = ROOT + 'witness/anchors.json'
const STATUS = ROOT + 'witness/status.json'
const TRUSTED_KEY = readFileSync(ROOT + 'witness/trusted-key.txt', 'utf8').trim()

const now = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z')
const lines = existsSync(HEADS) ? readFileSync(HEADS, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)) : []
const last = lines.at(-1) ?? null
const anchors = JSON.parse(readFileSync(ANCHORS, 'utf8'))

function alert(title, detail) {
  mkdirSync(ROOT + 'witness/alerts', { recursive: true })
  const f = `${ROOT}witness/alerts/${now.replace(/[:]/g, '-')}.md`
  writeFileSync(f, `# ALERT: ${title}\n\nObserved at ${now}.\n\n${detail}\n`)
  console.error(`ALERT: ${title}\n${detail}`)
  process.exit(2)
}

const sth = await (await fetch(STH_URL, { headers: { accept: 'application/json' } })).json()
const sig = verifySth(sth, TRUSTED_KEY)
if (!sig.ok) alert('head signature failed', `tree_size ${sth.tree_size}, root ${sth.root_hash}: ${sig.reason}`)

// The previous point of comparison: the last witnessed head, or a recorded anchor on first run.
const prev = last ? { size: last.tree_size, root: last.root_hash, kind: 'witnessed head' }
  : (() => { const sizes = Object.keys(anchors).map(Number).sort((a, b) => a - b); const s = sizes.at(-1); return s ? { size: s, root: anchors[String(s)], kind: 'recorded anchor' } : null })()

if (prev) {
  if (sth.tree_size < prev.size) alert('log shrank', `previous ${prev.kind}: size ${prev.size}; current head: size ${sth.tree_size}`)
  if (sth.tree_size === prev.size) {
    if (sth.root_hash !== prev.root) alert('root changed at the same size', `size ${prev.size}: recorded root ${prev.root}, current root ${sth.root_hash}`)
    writeFileSync(STATUS, JSON.stringify({ last_checked: now, last_size: sth.tree_size, last_root: sth.root_hash, heads_witnessed: lines.length, changed: false }, null, 2) + '\n')
    console.log(`unchanged: size ${sth.tree_size}, root ${sth.root_hash.slice(0, 12)}…`)
    process.exit(0)
  }
}

let proof = null
if (prev) {
  proof = await (await fetch(CONSISTENCY_URL + prev.size, { headers: { accept: 'application/json' } })).json()
  if (proof.new_size !== sth.tree_size || proof.new_root !== sth.root_hash) {
    // The log moved between the two requests. Try once more against the head the proof describes.
    const again = await (await fetch(STH_URL, { headers: { accept: 'application/json' } })).json()
    if (again.tree_size !== proof.new_size || again.root_hash !== proof.new_root) alert('head and proof disagree', `head ${sth.tree_size}/${sth.root_hash}; proof ${proof.new_size}/${proof.new_root}`)
    Object.assign(sth, again)
    const sig2 = verifySth(sth, TRUSTED_KEY)
    if (!sig2.ok) alert('head signature failed', sig2.reason)
  }
  const c = verifyConsistency(proof, prev.root, sth.root_hash)
  if (!c.ok) alert('consistency proof failed', `from ${prev.kind} size ${prev.size} root ${prev.root} to size ${sth.tree_size} root ${sth.root_hash}: ${c.reason}`)
}

const entry = {
  witnessed_at: now,
  tree_size: sth.tree_size,
  root_hash: sth.root_hash,
  timestamp: sth.timestamp,
  signature: sth.signature,
  key_id: sth.key_id,
  public_key: sth.public_key,
  consistency_from: prev ? prev.size : null,
  consistency_from_kind: prev ? prev.kind : null,
  consistency_path: proof ? proof.consistency_path : [],
}
appendFileSync(HEADS, JSON.stringify(entry) + '\n')
writeFileSync(`${ROOT}witness/heads/${String(sth.tree_size).padStart(8, '0')}.json`, JSON.stringify({ sth, consistency: proof }, null, 2) + '\n')
writeFileSync(STATUS, JSON.stringify({ last_checked: now, last_size: sth.tree_size, last_root: sth.root_hash, heads_witnessed: lines.length + 1, changed: true }, null, 2) + '\n')
console.log(`witnessed: size ${sth.tree_size}, root ${sth.root_hash.slice(0, 12)}…, consistent with ${prev ? `${prev.kind} at size ${prev.size}` : 'nothing (first head)'}`)
