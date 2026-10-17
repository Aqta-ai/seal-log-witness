// node --test test/*.test.mjs
// Fixtures: head.json and head.json.legacy.sigstore.json are the size 223 head file and the
// bundle cosign wrote for it. head.json.v03.sigstore.json carries the same Rekor entry in the
// protobuf bundle shape; its inclusion proof values are placeholders, used only for parsing.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { tlogEntryFromBundle, indexRow, buildIndex, statusSummary, checkLookup, leafHash, searchUrl } from '../scripts/rekor.mjs'

const fx = (n) => new URL(`./fixtures/${n}`, import.meta.url)
const headBytes = readFileSync(fx('head.json'))
const legacy = JSON.parse(readFileSync(fx('head.json.legacy.sigstore.json'), 'utf8'))
const v03 = JSON.parse(readFileSync(fx('head.json.v03.sigstore.json'), 'utf8'))
const headPath = 'witness/heads/00000223.json'
const LOG_INDEX = 2732650695
const LOG_ID = 'c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d'

test('reads the tlog entry from a legacy cosign bundle', () => {
  const e = tlogEntryFromBundle(legacy)
  assert.equal(e.log_index, LOG_INDEX)
  assert.equal(e.log_id, LOG_ID)
  assert.equal(e.integrated_time, 1788653545)
  assert.equal(e.proof_in_bundle, 'signed_entry_timestamp')
})

test('reads the same entry from a protobuf bundle', () => {
  const a = tlogEntryFromBundle(legacy), b = tlogEntryFromBundle(v03)
  assert.deepEqual({ ...b, proof_in_bundle: null }, { ...a, proof_in_bundle: null })
  assert.equal(b.proof_in_bundle, 'inclusion_proof_and_checkpoint')
})

test('builds an index row that points at the Sigstore search page', () => {
  const row = indexRow({ treeSize: 223, headPath, headBytes, bundle: legacy })
  assert.equal(row.head_file, headPath)
  assert.equal(row.bundle_file, `${headPath}.sigstore.json`)
  assert.equal(row.log_index, LOG_INDEX)
  assert.equal(row.search_url, `https://search.sigstore.dev/?logIndex=${LOG_INDEX}`)
  assert.equal(row.integrated_at, '2026-09-06T00:12:25Z')
  assert.match(row.leaf_hash, /^[0-9a-f]{64}$/)
  assert.equal(row.uuid, null)
})

test('refuses a bundle whose Rekor entry is for different bytes', () => {
  const tampered = Buffer.concat([headBytes, Buffer.from(' ')])
  assert.throws(() => indexRow({ treeSize: 223, headPath, headBytes: tampered, bundle: legacy }), /commits to sha256/)
})

test('keeps a looked-up UUID only when it ends in this entry\'s leaf hash', () => {
  const leaf = leafHash(legacy.rekorBundle.Payload.body)
  const kept = indexRow({ treeSize: 223, headPath, headBytes, bundle: legacy, previous: { uuid: '108e9186e8c5677a' + leaf } })
  assert.equal(kept.uuid, '108e9186e8c5677a' + leaf)
  const dropped = indexRow({ treeSize: 223, headPath, headBytes, bundle: legacy, previous: { uuid: '108e9186e8c5677a' + '0'.repeat(64) } })
  assert.equal(dropped.uuid, null)
})

test('indexes by tree size in ascending order and summarises the latest', () => {
  const row = indexRow({ treeSize: 223, headPath, headBytes, bundle: legacy })
  const later = { ...row, log_index: LOG_INDEX + 5, search_url: searchUrl(LOG_INDEX + 5) }
  const index = buildIndex([[1180, later], [223, row]])
  assert.deepEqual(Object.keys(index.entries), ['223', '1180'])
  assert.equal(index.latest_size, 1180)
  assert.equal(index.count, 2)
  assert.deepEqual(statusSummary(index), {
    rekor_index: 'witness/rekor-index.json',
    rekor_latest_size: 1180,
    rekor_latest_log_index: LOG_INDEX + 5,
    rekor_latest_search_url: searchUrl(LOG_INDEX + 5),
    rekor_entries: 2,
  })
  assert.equal(statusSummary(buildIndex([])).rekor_latest_log_index, null)
})

test('accepts a Rekor lookup that matches the bundle, rejects one that does not', () => {
  const row = indexRow({ treeSize: 223, headPath, headBytes, bundle: legacy })
  const body = legacy.rekorBundle.Payload.body
  const uuid = '108e9186e8c5677a' + row.leaf_hash
  const entry = { body, integratedTime: 1788653545, logID: LOG_ID, logIndex: LOG_INDEX }
  assert.equal(checkLookup({ [uuid]: entry }, row, body), uuid)
  assert.throws(() => checkLookup({ [uuid]: { ...entry, logIndex: LOG_INDEX + 1 } }, row, body), /disagree/)
  assert.throws(() => checkLookup({ [uuid]: { ...entry, body: Buffer.from('{}').toString('base64') } }, row, body), /body differs/)
  assert.throws(() => checkLookup({}, row, body), /expected one entry/)
})
