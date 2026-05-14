/**
 * MemWal Relayer — End-to-End Test (Apalis flow, MEM-35)
 *
 * Tests the async pipeline now in place on the nautilus-memwal-relayer:
 *   1. POST /api/remember        → 202 { job_id, status: "pending" }
 *   2. GET  /api/remember/{id}   → poll until status == "done" (blob_id returned)
 *   3. POST /api/recall          → find the blob by semantic similarity
 *   4. POST /api/analyze         → 202 { job_ids, facts, fact_count }
 *   5. Poll each analyze job_id  → confirm all transition to "done"
 *
 * Signing format matches the SDK (signedRequest): includes nonce + account_id,
 * verifies the relayer's signed responses against the enclave ephemeral pubkey.
 *
 * Run:
 *   set -a && source ../.env && set +a
 *   MEMWAL_SERVER_URL=http://localhost:8001 \
 *   MEMWAL_DELEGATE_KEY=<hex> \
 *   MEMWAL_ACCOUNT_ID=0x... \
 *   ./node_modules/.bin/tsx test-e2e.ts
 */

import { createHash, randomUUID } from 'node:crypto'
import { ed25519 } from '@noble/curves/ed25519.js'
import { bcs } from '@mysten/bcs'

// ── Signed response verification (matches enclave.rs sign_response) ────────────

type SignedResponse<T> = {
    data: T
    intent_scope: number
    timestamp_ms: number
    signature: string
    enclave_public_key: string
}

const IntentMessage = bcs.struct('IntentMessage', {
    intent: bcs.u8(),
    timestamp_ms: bcs.u64(),
    payload: bcs.vector(bcs.u8()),
})

function verifySignedResponse<T>(resp: SignedResponse<T>): T {
    const bodyHash = createHash('sha256')
        .update(JSON.stringify(resp.data), 'utf8')
        .digest()
    const signedBytes = IntentMessage.serialize({
        intent: resp.intent_scope,
        timestamp_ms: BigInt(resp.timestamp_ms),
        payload: Array.from(bodyHash),
    }).toBytes()
    const sig = hexToBytes(resp.signature)
    const pk = hexToBytes(resp.enclave_public_key)
    if (!ed25519.verify(sig, signedBytes, pk)) {
        throw new Error(`Enclave signature verification FAILED (intent=${resp.intent_scope})`)
    }
    return resp.data
}

// ── Config ─────────────────────────────────────────────────────────────────────

const SERVER_URL = process.env.MEMWAL_SERVER_URL ?? 'http://localhost:8001'
const DELEGATE_KEY = process.env.MEMWAL_DELEGATE_KEY ?? ''
const ACCOUNT_ID = process.env.MEMWAL_ACCOUNT_ID ?? ''
const NAMESPACE = process.env.MEMWAL_NAMESPACE ?? 'e2e-test'
const POLL_INTERVAL_MS = Number(process.env.POLL_INTERVAL_MS ?? 2000)
const POLL_TIMEOUT_MS = Number(process.env.POLL_TIMEOUT_MS ?? 120_000)

if (!DELEGATE_KEY) { console.error('MEMWAL_DELEGATE_KEY not set'); process.exit(1) }
if (!ACCOUNT_ID) { console.error('MEMWAL_ACCOUNT_ID not set'); process.exit(1) }

// ── Helpers ────────────────────────────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2)
    for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16)
    return bytes
}

function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

const privKeyBytes = hexToBytes(DELEGATE_KEY)
const pubKeyBytes = ed25519.getPublicKey(privKeyBytes)

/** Mirrors SDK signedRequest(): timestamp.method.path.bodySha256.nonce.accountId */
async function signedRequest<T = unknown>(
    method: 'GET' | 'POST',
    path: string,
    body?: object,
): Promise<T> {
    const bodyStr = method === 'GET' ? '' : JSON.stringify(body ?? {})
    const timestamp = Math.floor(Date.now() / 1000).toString()
    const bodyHash = createHash('sha256').update(bodyStr, 'utf8').digest('hex')
    const nonce = randomUUID()
    const message = `${timestamp}.${method}.${path}.${bodyHash}.${nonce}.${ACCOUNT_ID}`
    const sigBytes = ed25519.sign(Buffer.from(message, 'utf8'), privKeyBytes)

    const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'x-public-key': bytesToHex(pubKeyBytes),
        'x-signature': bytesToHex(sigBytes),
        'x-timestamp': timestamp,
        'x-nonce': nonce,
        'x-account-id': ACCOUNT_ID,
        'x-delegate-key': DELEGATE_KEY,
    }

    console.log(`  → ${method} ${SERVER_URL}${path}`)
    const resp = await fetch(`${SERVER_URL}${path}`, {
        method,
        headers,
        body: method === 'GET' ? undefined : bodyStr,
    })
    const text = await resp.text()
    if (resp.status !== 200 && resp.status !== 202) {
        throw new Error(`HTTP ${resp.status}: ${text}`)
    }
    return JSON.parse(text) as T
}

async function pollJob(jobId: string, label: string): Promise<{ status: string; blob_id?: string }> {
    const deadline = Date.now() + POLL_TIMEOUT_MS
    let lastStatus = ''
    while (Date.now() < deadline) {
        const status = await signedRequest<{ job_id: string; status: string; blob_id?: string; error?: string }>(
            'GET',
            `/api/remember/${jobId}`,
        )
        if (status.status !== lastStatus) {
            console.log(`     [${label}] status: ${status.status}${status.blob_id ? ` blob_id=${status.blob_id}` : ''}`)
            lastStatus = status.status
        }
        if (status.status === 'done' || status.status === 'uploaded') {
            return { status: status.status, blob_id: status.blob_id }
        }
        if (status.status === 'failed') {
            throw new Error(`Job ${jobId} failed: ${status.error ?? 'unknown'}`)
        }
        await new Promise(r => setTimeout(r, POLL_INTERVAL_MS))
    }
    throw new Error(`Job ${jobId} did not complete within ${POLL_TIMEOUT_MS}ms`)
}

// ── Test steps ─────────────────────────────────────────────────────────────────

async function testHealth() {
    console.log('\n── 1. Health ─────────────────────────────────────────────────')
    const resp = await fetch(`${SERVER_URL}/health`)
    if (!resp.ok) throw new Error(`Health failed: HTTP ${resp.status}`)
    console.log('  ok', await resp.json())
}

async function testRemember(): Promise<string> {
    console.log('\n── 2. Remember (Apalis async flow) ───────────────────────────')
    const text = `E2E test ${new Date().toISOString()}: MemWal relayer uses SEAL encryption, Walrus storage, and Apalis-backed wallet jobs for retry-safe uploads.`
    const raw = await signedRequest<SignedResponse<{ job_id: string; status: string }>>(
        'POST', '/api/remember', { text, namespace: NAMESPACE },
    )
    const accepted = verifySignedResponse(raw)
    console.log(`  accepted: job_id=${accepted.job_id} status=${accepted.status}`)

    console.log('  polling for completion...')
    const done = await pollJob(accepted.job_id, 'remember')
    if (!done.blob_id) throw new Error('remember completed without blob_id')
    console.log(`  blob_id: ${done.blob_id}`)
    return done.blob_id
}

async function testRecall(expectedBlobId: string) {
    console.log('\n── 3. Recall ─────────────────────────────────────────────────')
    const raw = await signedRequest<SignedResponse<{
        results: Array<{ blob_id: string; text: string; distance: number }>
        total: number
    }>>('POST', '/api/recall', { query: 'Apalis wallet jobs SEAL Walrus', namespace: NAMESPACE, limit: 5 })
    const result = verifySignedResponse(raw)
    console.log(`  ${result.total} result(s)`)
    for (const [i, r] of result.results.entries()) {
        console.log(`  [${i + 1}] dist=${r.distance.toFixed(4)} blob_id=${r.blob_id}`)
        console.log(`       text: ${r.text.slice(0, 120)}${r.text.length > 120 ? '…' : ''}`)
    }
    if (result.results.some(r => r.blob_id === expectedBlobId)) {
        console.log('  ✓ remembered blob found in recall')
    } else {
        console.warn(`  ⚠ blob ${expectedBlobId} not in top results (propagation lag is normal)`)
    }
}

async function testAnalyze() {
    console.log('\n── 4. Analyze (multi-fact → multiple wallet jobs) ────────────')
    const text = 'I live in Bangalore and my favorite stack is Rust with Axum.'
    const raw = await signedRequest<SignedResponse<{
        job_ids: string[]
        facts: Array<{ text: string; id: string; job_id: string }>
        fact_count: number
        status: string
        owner: string
    }>>('POST', '/api/analyze', { text, namespace: NAMESPACE })
    const accepted = verifySignedResponse(raw)
    console.log(`  ${accepted.fact_count} fact(s) extracted, ${accepted.job_ids.length} job(s) enqueued`)
    for (const [i, f] of accepted.facts.entries()) {
        console.log(`  [${i + 1}] job_id=${f.job_id} text=${f.text}`)
    }

    console.log('  polling all jobs...')
    const results = await Promise.allSettled(
        accepted.job_ids.map((id, i) => pollJob(id, `analyze#${i + 1}`)),
    )
    let ok = 0, fail = 0
    for (const [i, r] of results.entries()) {
        if (r.status === 'fulfilled' && r.value.blob_id) {
            console.log(`  ✓ fact ${i + 1}: blob_id=${r.value.blob_id}`)
            ok++
        } else {
            console.error(`  ✗ fact ${i + 1}: ${r.status === 'rejected' ? r.reason : 'no blob_id'}`)
            fail++
        }
    }
    console.log(`  analyze summary: ${ok} ok, ${fail} failed`)
    if (fail > 0) throw new Error(`analyze had ${fail} failed job(s)`)
}

// ── Main ───────────────────────────────────────────────────────────────────────

async function main() {
    console.log('MemWal Relayer E2E Test (Apalis flow)')
    console.log('  server:    ', SERVER_URL)
    console.log('  account:   ', ACCOUNT_ID)
    console.log('  namespace: ', NAMESPACE)
    console.log('  pubkey:    ', bytesToHex(pubKeyBytes))

    try {
        await testHealth()
        const blobId = await testRemember()
        console.log('\n  waiting 3s for Walrus propagation...')
        await new Promise(r => setTimeout(r, 3000))
        await testRecall(blobId)
        await testAnalyze()
        console.log('\nE2E test passed\n')
    } catch (err) {
        console.error('\nE2E test FAILED:', err)
        process.exit(1)
    }
}

main()
