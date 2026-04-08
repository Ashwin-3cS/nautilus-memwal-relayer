# nautilus-memwal-relayer

A self-hostable [MemWal](https://github.com/MystenLabs/MemWal) relay running inside an **AWS Nitro Enclave** via the [Nautilus](https://github.com/MystenLabs/nautilus) TEE framework.

MemWal's managed relayer is shared infrastructure — the operator can see plaintext memories and embeddings in transit. This template lets you run the relay in a hardware-attested TEE so that no one, including the host OS operator, can read your data in transit.

---

## Trust model

| Feature | Status |
|---|---|
| SEAL encryption (client-side key, server never holds plaintext key material) | done |
| Walrus decentralized storage (blobs owned on-chain by user account) | done |
| AWS Nitro hardware attestation — proves exact enclave image via PCRs | done |
| Ephemeral enclave signing key — all API responses signed, verifiable by client | done |
| Reproducible stagex build — PCR0 stable across rebuilds | done |

---

## Attestation endpoints

### `GET /enclave_health`

Returns the enclave ephemeral Ed25519 public key. Generated fresh on every enclave start using NSM entropy; never exposed outside the enclave.

```json
{ "public_key": "d54795ba...", "status": "ok" }
```

### `GET /get_attestation`

Returns the raw NSM attestation document (hex-encoded CBOR). Binds the ephemeral public key to the enclave image PCRs. Clients use this to verify they are talking to a genuine Nitro enclave running the expected code.

```bash
curl http://<host>:4000/get_attestation
# -> {"attestation":"8444a1..."}
```

Parse the CBOR doc to extract PCRs and verify the AWS cert chain with any standard NSM verifier (e.g. `@aws-nitro-enclaves/attestation`).

### `GET /logs?lines=N`

Tail the last N (default 100, max 1000) in-memory log lines from inside the enclave.

---

## Signed API responses

Every protected endpoint (`/api/remember`, `/api/recall`, `/api/analyze`, `/api/ask`, `/api/restore`, and their manual variants) wraps its response in a signed envelope:

```json
{
  "data": { ... },
  "signature": "<hex Ed25519 sig over JSON bytes of data>",
  "enclave_public_key": "<hex — same key as /enclave_health>"
}
```

**Verification (TypeScript / `@noble/curves`):**

```ts
import { ed25519 } from '@noble/curves/ed25519.js'

const payload = new TextEncoder().encode(JSON.stringify(response.data))
const ok = ed25519.verify(
  fromHex(response.signature),
  payload,
  fromHex(response.enclave_public_key)
)
```

The trust chain is:

```
GET /get_attestation
  -> NSM doc with PCRs + ephemeral pubkey (AWS cert chain)
      -> verify PCR0 matches your reproducible build
          -> trust enclave_public_key
              -> verify every API response signature
```

---

## Outbound proxies (VSOCK bridges)

Inside the enclave all outbound traffic routes through host-side socat VSOCK bridges:

| Service | Loopback | VSOCK port |
|---|---|---|
| Sui RPC | 127.0.0.2 | 8101 |
| Walrus publisher | 127.0.0.3 | 8102 |
| Walrus aggregator | 127.0.0.4 | 8103 |
| Postgres (Supabase) | 127.0.0.5 | 8104 |
| Redis (Upstash) | 127.0.0.6 | 8105 |
| OpenAI / OpenRouter | 127.0.0.7 | 8106 |
| SEAL key servers | 127.0.0.8+ | 8107+ |
| Embedding (Jina) | 127.0.0.9 | 8108 |
| Walrus upload relay | 127.0.0.10 | 8109 |

---

## Quick start

### 1. Configure secrets

Copy `.env.example` to `.env.memwal` and fill in your values. Store the entire file as the `MEMWAL_ENV_FILE` GitHub Actions secret.

### 2. Init CI

```bash
cd your-project
nautilus init-ci   # generates .github/workflows/build-and-publish.yml
```

Or manually trigger the included `deploy.yml` workflow.

### 3. Run the e2e test

```bash
cd src/relayer/scripts
npm ci
MEMWAL_SERVER_URL=http://<host>:4000 \
MEMWAL_DELEGATE_KEY=<hex> \
MEMWAL_ACCOUNT_ID=0x... \
./node_modules/.bin/tsx test-e2e.ts
```

The test verifies the enclave signature on every response automatically.

---

## Architecture

The enclave runs two processes:

- **Rust HTTP server** (`memwal_server`) — auth, rate limiting, vector DB, orchestration
- **TypeScript sidecar** (`sidecar-server.ts`, Node 22 + tsx) — SEAL encrypt/decrypt, Walrus `writeBlobFlow` (on-chain blob ownership)

The sidecar is spawned by the Rust server and managed via HTTP on `localhost:9000`. Both run inside the same Nitro enclave image.

---

## Reproducible build

```bash
make build
# -> out/nitro.eif  (enclave image)
# -> out/nitro.pcrs (PCR0/1/2 values)
```

PCR0 is stable across rebuilds — use it to pin your on-chain enclave cap (Phase 2).
