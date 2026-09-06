# seal-log-witness

An hourly, independent record of the signed heads of Aqta's public transparency log for Seal
receipts and action records, kept outside Aqta's infrastructure, with every new head signed into
Sigstore's public log by this repository's GitHub Actions identity.

A transparency log is only as good as the parties watching it. Aqta publishes a signed head at
`https://api.aqta.ai/v1/public/transparency/sth` and serves inclusion and consistency proofs.
Anyone can pin a head in their browser at `app.aqta.ai/transparency`. This repository does the
same thing on a schedule, in public, so that the log's history is held somewhere Aqta cannot
quietly rewrite.

## What one run does

1. Fetches the current head and checks its Ed25519 signature under the pinned issuer key in
   `witness/trusted-key.txt`. A head that names a different key fails.
2. Fetches a consistency proof from the last head recorded here to the current one, and checks
   it (RFC 6962, section 2.1.2). The first record proved consistency from an earlier root Aqta
   recorded in `witness/anchors.json`.
3. Appends the head and its proof to `witness/heads.jsonl` and `witness/heads/<size>.json`.
4. Re-verifies the entire chain offline from the files alone (`scripts/check.mjs`).
5. Signs the new head file into Sigstore's Rekor log with the workflow's GitHub OIDC identity
   (`cosign sign-blob`), so a third party holds a timestamped record that this file existed.
6. Commits. An unchanged head still updates `witness/status.json`, which is the heartbeat.

A log that shrinks, changes a root at the same size, fails its signature, or fails a
consistency proof makes the job fail and leaves a file in `witness/alerts/`.

## Check it yourself

```bash
git clone https://github.com/Aqta-ai/seal-log-witness && cd seal-log-witness
node scripts/check.mjs            # every signature and every consistency proof, offline
node scripts/witness.mjs          # fetch the live head and prove it extends the last one here
cosign verify-blob --bundle witness/heads/<size>.json.sigstore.json \
  --certificate-identity-regexp '^https://github.com/Aqta-ai/seal-log-witness/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com witness/heads/<size>.json
```

No dependencies beyond Node 20 for the first two. `cosign` is Sigstore's tool.

## What this proves, and what it does not

It proves that the sequence of heads recorded here was published by the holder of the pinned
key, that each head extends the previous one without rewriting anything beneath it, and that each
record existed at the time Sigstore countersigned it. It does not prove anything about the
content of the log's entries, which are hashes, and it does not make the witness independent of
Aqta in the strongest sense: Aqta operates this repository. Its independence comes from where the
evidence lives, in GitHub's commit history and Sigstore's public log, and from the fact that
anyone can fork this repository and run the same script on their own schedule. If you run one,
tell security@aqta.ai and it will be listed here.

## Provenance of the starting point

The log was re-anchored at size 153 on 27 August 2026 after an ordering defect, which is stated
on `app.aqta.ai/transparency`. The size 196 root in `witness/anchors.json` was recorded by Aqta on
4 September 2026, immediately before action records were added to the log, and the first head
witnessed here carries the consistency proof from that root.

Licence: Apache-2.0. Scripts mirror `dashboard/lib/transparency-client.ts` in `Aqta-ai/aqta-app`.
