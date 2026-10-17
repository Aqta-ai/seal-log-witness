#!/usr/bin/env node
// Build witness/rekor-index.json, mapping each witnessed tree size to the Sigstore Rekor entry that
// countersigned its head file, from the bundles alone. Adds a summary to witness/status.json.
//
//   node scripts/rekor-index.mjs            offline: every field the bundles hold
//   node scripts/rekor-index.mjs --lookup   also fills each missing full UUID with a read-only
//                                           Rekor v1 lookup by log index, at most one per second,
//                                           and checks the entry Rekor returns against the bundle
//
// A lookup that cannot reach Rekor leaves the UUID empty for the next run. A lookup that reaches
// Rekor and disagrees with the bundle exits 2.
import { readFileSync, writeFileSync, readdirSync, existsSync } from 'node:fs'
import { REKOR_URL, indexRow, buildIndex, statusSummary, checkLookup, tlogEntryFromBundle } from './rekor.mjs'

const ROOT = new URL('..', import.meta.url).pathname
const HEADS_DIR = 'witness/heads'
const INDEX = ROOT + 'witness/rekor-index.json'
const STATUS = ROOT + 'witness/status.json'
const LOOKUP = process.argv.includes('--lookup')
const PACE_MS = 1100

const previous = existsSync(INDEX) ? JSON.parse(readFileSync(INDEX, 'utf8')).entries ?? {} : {}
const rows = []
const bodies = new Map()
for (const name of readdirSync(ROOT + HEADS_DIR).filter((n) => /^\d{8}\.json$/.test(n)).sort()) {
  const headPath = `${HEADS_DIR}/${name}`
  if (!existsSync(`${ROOT}${headPath}.sigstore.json`)) {
    console.log(`no bundle yet: ${headPath}`)
    continue
  }
  const size = Number(name.slice(0, 8))
  const bundle = JSON.parse(readFileSync(`${ROOT}${headPath}.sigstore.json`, 'utf8'))
  const row = indexRow({ treeSize: size, headPath, headBytes: readFileSync(ROOT + headPath), bundle, previous: previous[String(size)] })
  bodies.set(size, tlogEntryFromBundle(bundle).body)
  rows.push([size, row])
}

if (LOOKUP) {
  let first = true
  for (const [size, row] of rows) {
    if (row.uuid) continue
    if (!first) await new Promise((r) => setTimeout(r, PACE_MS))
    first = false
    let res
    try {
      const r = await fetch(`${REKOR_URL}/api/v1/log/entries?logIndex=${row.log_index}`, { headers: { accept: 'application/json' }, signal: AbortSignal.timeout(15000) })
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
      res = await r.json()
    } catch (err) {
      console.log(`size ${size}: Rekor lookup unavailable (${err.message}); UUID left for the next run`)
      continue
    }
    try {
      row.uuid = checkLookup(res, row, bodies.get(size))
    } catch (err) {
      console.error(`ALERT: ${err.message}`)
      process.exit(2)
    }
  }
}

const index = buildIndex(rows)
writeFileSync(INDEX, JSON.stringify(index, null, 2) + '\n')
if (existsSync(STATUS)) {
  const status = JSON.parse(readFileSync(STATUS, 'utf8'))
  writeFileSync(STATUS, JSON.stringify({ ...status, ...statusSummary(index) }, null, 2) + '\n')
}
const latest = index.latest_size === null ? null : index.entries[String(index.latest_size)]
console.log(`rekor index: ${index.count} entr${index.count === 1 ? 'y' : 'ies'}${latest ? `, latest size ${index.latest_size} at Rekor log index ${latest.log_index}` : ''}`)
