// Read the Rekor transparency log entry that a cosign bundle already carries, and build the
// tree_size -> Rekor entry index from it. No network here: lookups live in rekor-index.mjs.
// Handles both bundle shapes cosign writes: the legacy one (rekorBundle.Payload, cosign v2
// default) and the Sigstore protobuf bundle (verificationMaterial.tlogEntries, cosign v3).
import { createHash } from 'node:crypto'

export const REKOR_URL = 'https://rekor.sigstore.dev'
export const searchUrl = (logIndex) => `https://search.sigstore.dev/?logIndex=${logIndex}`
const sha256 = (b) => createHash('sha256').update(b).digest('hex')

/** RFC 6962 leaf hash of the canonicalized entry body: Rekor's entry UUID without the tree ID. */
export const leafHash = (bodyB64) => sha256(Buffer.concat([Buffer.from([0]), Buffer.from(bodyB64, 'base64')]))

/** The tlog entry a bundle holds, normalised. Throws if the bundle carries none. */
export function tlogEntryFromBundle(bundle) {
  const legacy = bundle?.rekorBundle?.Payload
  if (legacy) {
    return {
      log_index: Number(legacy.logIndex),
      log_id: String(legacy.logID).toLowerCase(),
      integrated_time: Number(legacy.integratedTime),
      body: legacy.body,
      proof_in_bundle: bundle.rekorBundle.SignedEntryTimestamp ? 'signed_entry_timestamp' : 'none',
    }
  }
  const t = bundle?.verificationMaterial?.tlogEntries?.[0]
  if (t) {
    const proof = t.inclusionProof
    return {
      log_index: Number(t.logIndex),
      log_id: Buffer.from(t.logId.keyId, 'base64').toString('hex'),
      integrated_time: Number(t.integratedTime),
      body: t.canonicalizedBody,
      proof_in_bundle: proof ? (proof.checkpoint ? 'inclusion_proof_and_checkpoint' : 'inclusion_proof') : (t.inclusionPromise ? 'signed_entry_timestamp' : 'none'),
    }
  }
  throw new Error('bundle carries no Rekor tlog entry')
}

/** The artifact digest the Rekor entry commits to, for a hashedrekord body. */
export function artifactDigest(bodyB64) {
  const body = JSON.parse(Buffer.from(bodyB64, 'base64').toString('utf8'))
  const h = body?.spec?.data?.hash
  if (body.kind !== 'hashedrekord' || !h) throw new Error(`unexpected Rekor entry kind ${body.kind}`)
  return { algorithm: h.algorithm, value: h.value }
}

/**
 * One index row for a head file and its bundle. Fails if the Rekor entry does not commit to the
 * bytes of the head file, so the index can only point at the entry for the file it names.
 */
export function indexRow({ treeSize, headPath, headBytes, bundle, previous }) {
  const e = tlogEntryFromBundle(bundle)
  const d = artifactDigest(e.body)
  if (d.algorithm !== 'sha256' || d.value !== sha256(headBytes)) {
    throw new Error(`size ${treeSize}: Rekor entry commits to ${d.algorithm}:${d.value}, head file is sha256:${sha256(headBytes)}`)
  }
  const leaf = leafHash(e.body)
  // A full UUID (tree ID + leaf hash) is kept from an earlier lookup only if it is for this leaf.
  const uuid = previous?.uuid && previous.uuid.endsWith(leaf) ? previous.uuid : null
  return {
    head_file: headPath,
    bundle_file: `${headPath}.sigstore.json`,
    log_index: e.log_index,
    log_id: e.log_id,
    integrated_time: e.integrated_time,
    integrated_at: new Date(e.integrated_time * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z'),
    leaf_hash: leaf,
    uuid,
    proof_in_bundle: e.proof_in_bundle,
    search_url: searchUrl(e.log_index),
  }
}

/** The index: rows keyed by tree size, in ascending order. */
export function buildIndex(rows) {
  const entries = {}
  for (const [size, row] of [...rows].sort((a, b) => a[0] - b[0])) entries[String(size)] = row
  const sizes = Object.keys(entries).map(Number)
  return { v: 1, rekor: REKOR_URL, latest_size: sizes.at(-1) ?? null, count: sizes.length, entries }
}

/** Fields added to status.json. Existing fields are left exactly as they are. */
export function statusSummary(index) {
  const latest = index.latest_size === null ? null : index.entries[String(index.latest_size)]
  return {
    rekor_index: 'witness/rekor-index.json',
    rekor_latest_size: index.latest_size,
    rekor_latest_log_index: latest ? latest.log_index : null,
    rekor_latest_search_url: latest ? latest.search_url : null,
    rekor_entries: index.count,
  }
}

/**
 * Check a Rekor v1 GET /api/v1/log/entries response against what the bundle says, and return the
 * full UUID. A mismatch means the public log and the bundle disagree, which is never ignored.
 */
export function checkLookup(response, row, bundleBody) {
  const pairs = Object.entries(response ?? {})
  if (pairs.length !== 1) throw new Error(`log index ${row.log_index}: expected one entry, got ${pairs.length}`)
  const [uuid, entry] = pairs[0]
  const problems = []
  if (Number(entry.logIndex) !== row.log_index) problems.push(`logIndex ${entry.logIndex}`)
  if (Number(entry.integratedTime) !== row.integrated_time) problems.push(`integratedTime ${entry.integratedTime}`)
  if (String(entry.logID).toLowerCase() !== row.log_id) problems.push(`logID ${entry.logID}`)
  if (!Buffer.from(entry.body, 'base64').equals(Buffer.from(bundleBody, 'base64'))) problems.push('body differs from the bundle')
  if (!uuid.endsWith(row.leaf_hash)) problems.push(`uuid ${uuid} does not end in the leaf hash`)
  if (problems.length) throw new Error(`log index ${row.log_index}: Rekor and the bundle disagree: ${problems.join('; ')}`)
  return uuid
}
