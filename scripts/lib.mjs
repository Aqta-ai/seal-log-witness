// Shared verification for the Seal public log witness. No dependencies: Node 20 crypto only.
// Mirrors dashboard/lib/transparency-client.ts in Aqta-ai/aqta-app so the two cannot drift.
import { createHash, createPublicKey, verify as edVerify } from 'node:crypto'

export const STH_URL = 'https://api.aqta.ai/v1/public/transparency/sth'
export const CONSISTENCY_URL = 'https://api.aqta.ai/v1/public/transparency/consistency?old_size='
const STH_PREFIX = 'aqta-sth-public-v1|'
const B64URL_STRICT = /^[A-Za-z0-9_-]+$/

export function b64urlDecode(s) {
  if (!B64URL_STRICT.test(s)) throw new Error('not base64url')
  return Buffer.from(s, 'base64url')
}
export const hexToBytes = (h) => Buffer.from(h, 'hex')
export const bytesToHex = (b) => Buffer.from(b).toString('hex')
const sha256 = (b) => createHash('sha256').update(b).digest()
const nodeHash = (l, r) => sha256(Buffer.concat([Buffer.from([1]), l, r]))

/** Ed25519 over PREFIX || size || "|" || root bytes || "|" || timestamp, under the trusted key. */
export function verifySth(sth, trustedKey) {
  if (sth.public_key && sth.public_key !== trustedKey) {
    return { ok: false, reason: `head names key ${sth.public_key}, witness trusts ${trustedKey}` }
  }
  const msg = Buffer.concat([
    Buffer.from(STH_PREFIX + String(sth.tree_size) + '|', 'utf8'),
    hexToBytes(sth.root_hash),
    Buffer.from('|' + sth.timestamp, 'utf8'),
  ])
  const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(b64urlDecode(trustedKey)).toString('base64url') }, format: 'jwk' })
  const ok = edVerify(null, msg, key, b64urlDecode(sth.signature))
  return ok ? { ok } : { ok: false, reason: 'signature does not verify under the trusted key' }
}

/** RFC 6962 section 2.1.2 consistency check between an earlier root and the current one. */
export function verifyConsistency(proof, pinnedRoot, currentRoot) {
  const first = proof.old_size, second = proof.new_size
  if (first === second) {
    const ok = pinnedRoot === currentRoot && proof.consistency_path.length === 0
    return ok ? { ok } : { ok: false, reason: 'same size but roots differ' }
  }
  if (first < 1 || first > second) return { ok: false, reason: 'invalid sizes' }
  const path = proof.consistency_path.map(hexToBytes)
  let fn = first - 1, sn = second - 1
  while (fn % 2 === 1) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2) }
  let i = 0, fr, sr
  if (fn === 0) { fr = hexToBytes(pinnedRoot); sr = hexToBytes(pinnedRoot) }
  else {
    if (path.length === 0) return { ok: false, reason: 'consistency path empty' }
    fr = path[0]; sr = path[0]; i = 1
  }
  while (fn > 0 || sn > 0) {
    if (i >= path.length) return { ok: false, reason: 'consistency path too short' }
    if (fn % 2 === 1 || fn === sn) {
      fr = nodeHash(path[i], fr); sr = nodeHash(path[i], sr)
      while (fn % 2 === 0 && fn !== 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2) }
      i++
    } else { sr = nodeHash(sr, path[i]); i++ }
    fn = Math.floor(fn / 2); sn = Math.floor(sn / 2)
  }
  if (bytesToHex(fr) !== pinnedRoot.toLowerCase()) return { ok: false, reason: 'pinned root is not a prefix of the current log' }
  if (bytesToHex(sr) !== currentRoot.toLowerCase()) return { ok: false, reason: 'current root does not match the proof' }
  if (i !== path.length) return { ok: false, reason: 'consistency path has unused elements' }
  return { ok: true }
}
