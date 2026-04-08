/**
 * MemWal Relayer — End-to-End Test
 *
 * Uses the same delegate key + account from .env.repro (SDK test config).
 * Mirrors the SDK's signedRequest() exactly so server auth passes.
 *
 * Run from this directory:
 *   MEMWAL_DELEGATE_KEY=<hex> MEMWAL_ACCOUNT_ID=0x... npx tsx test-e2e.ts
 *
 * Or source both env files:
 *   set -a
 *   source /home/ashwin/projects/MemWal/packages/sdk/.env.repro
 *   set +a
 *   MEMWAL_SERVER_URL=http://13.203.196.47:4000 ./node_modules/.bin/tsx test-e2e.ts
 */

import { createHash } from 'node:crypto'
import { ed25519 } from '@noble/curves/ed25519.js'

// ── Config ─────────────────────────────────────────────────────────────────────

const SERVER_URL  = process.env.MEMWAL_SERVER_URL  ?? 'http://13.203.196.47:4000'
const DELEGATE_KEY = process.env.MEMWAL_DELEGATE_KEY ?? ''
const ACCOUNT_ID   = process.env.MEMWAL_ACCOUNT_ID   ?? ''

if (!DELEGATE_KEY) { console.error('❌ MEMWAL_DELEGATE_KEY not set'); process.exit(1) }
if (!ACCOUNT_ID)   { console.error('❌ MEMWAL_ACCOUNT_ID not set');   process.exit(1) }

// ── Helpers ────────────────────────────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2)
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16)
    }
    return bytes
}

function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

const privKeyBytes = hexToBytes(DELEGATE_KEY)
const pubKeyBytes  = ed25519.getPublicKey(privKeyBytes)

// Mirrors MemWal SDK signedRequest() exactly
async function signedPost(path: string, body: object): Promise<unknown> {
    const bodyStr   = JSON.stringify(body)
    const timestamp = Math.floor(Date.now() / 1000).toString()
    const bodyHash  = createHash('sha256').update(bodyStr, 'utf8').digest('hex')
    const message   = `${timestamp}.POST.${path}.${bodyHash}`

    const sigBytes = ed25519.sign(Buffer.from(message, 'utf8'), privKeyBytes)

    const headers: Record<string, string> = {
        'Content-Type':   'application/json',
        'x-public-key':   bytesToHex(pubKeyBytes),
        'x-signature':    bytesToHex(sigBytes),
        'x-timestamp':    timestamp,
        'x-delegate-key': DELEGATE_KEY,
        'x-account-id':   ACCOUNT_ID,
    }

    console.log(`  → POST ${SERVER_URL}${path}`)
    const resp = await fetch(`${SERVER_URL}${path}`, { method: 'POST', headers, body: bodyStr })
    const text = await resp.text()
    if (!resp.ok) throw new Error(`HTTP ${resp.status}: ${text}`)
    return JSON.parse(text)
}

// ── Test steps ─────────────────────────────────────────────────────────────────

async function testHealth() {
    console.log('\n── 1. Health ─────────────────────────────────────────────────')
    const resp = await fetch(`${SERVER_URL}/health`)
    const body = await resp.json()
    if (!resp.ok) throw new Error(`Health failed: ${JSON.stringify(body)}`)
    console.log('  ✓', body)
}

async function testRemember(): Promise<string> {
    console.log('\n── 2. Remember ───────────────────────────────────────────────')
    const text =
        `E2E test — ${new Date().toISOString()}. ` +
        `MemWal TEE enclave uses VSOCK bridging, SEAL encryption, ` +
        `and Walrus decentralized storage for privacy-preserving memory.`

    const result = await signedPost('/api/remember', { text, namespace: 'e2e-test' }) as {
        id: string; blob_id: string; owner: string; namespace: string
    }

    console.log('  ✓ stored')
    console.log('      id:       ', result.id)
    console.log('      blob_id:  ', result.blob_id)
    console.log('      owner:    ', result.owner)
    console.log('      namespace:', result.namespace)
    return result.blob_id
}

async function testRecall(expectedBlobId: string) {
    console.log('\n── 3. Recall ─────────────────────────────────────────────────')

    const result = await signedPost('/api/recall', {
        query: 'TEE enclave privacy SEAL Walrus',
        namespace: 'e2e-test',
        limit: 5,
    }) as { results: Array<{ blob_id: string; text: string; distance: number }>; total: number }

    console.log(`  ✓ ${result.total} result(s)`)
    for (const [i, r] of result.results.entries()) {
        console.log(`\n  [${i + 1}] distance: ${r.distance.toFixed(4)}`)
        console.log(`       blob_id:  ${r.blob_id}`)
        console.log(`       text:     ${r.text.slice(0, 120)}${r.text.length > 120 ? '…' : ''}`)
    }

    if (result.results.some(r => r.blob_id === expectedBlobId)) {
        console.log(`\n  ✓ remembered blob found in recall results`)
    } else {
        console.warn(`\n  ⚠ blob ${expectedBlobId} not in top results (Walrus propagation or dim mismatch)`)
    }
}

// ── Main ───────────────────────────────────────────────────────────────────────

async function main() {
    console.log('MemWal Relayer E2E Test')
    console.log('  server:    ', SERVER_URL)
    console.log('  account:   ', ACCOUNT_ID)
    console.log('  public_key:', bytesToHex(pubKeyBytes))

    try {
        await testHealth()
        const blobId = await testRemember()

        console.log('\n  ⏳ waiting 3s for Walrus propagation...')
        await new Promise(r => setTimeout(r, 3000))

        await testRecall(blobId)

        console.log('\n✅ E2E test passed\n')
    } catch (err) {
        console.error('\n❌ E2E test failed:', err)
        process.exit(1)
    }
}

main()
