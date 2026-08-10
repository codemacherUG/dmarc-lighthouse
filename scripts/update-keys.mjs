#!/usr/bin/env node
/**
 * Generate an Ed25519 keypair for update-manifest signing.
 * Writes keys/ (gitignored). Prints the SPKI base64 to paste into update-trust.ts.
 */
import { generateKeyPairSync } from 'node:crypto'
import { mkdirSync, writeFileSync, existsSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const dir = join(root, 'keys')
const privPath = join(dir, 'update-ed25519-private.pem')
const pubPath = join(dir, 'update-ed25519-public.pem')
const b64Path = join(dir, 'update-ed25519-public.b64')

if (existsSync(privPath) && process.argv[2] !== '--force') {
  console.error(`Already exists: ${privPath}`)
  console.error('Re-run with --force to overwrite (then update UPDATE_MANIFEST_PUBLIC_KEY_SPKI_B64).')
  process.exit(1)
}

mkdirSync(dir, { recursive: true, mode: 0o700 })
const { publicKey, privateKey } = generateKeyPairSync('ed25519')
const pubPem = publicKey.export({ type: 'spki', format: 'pem' })
const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' })
const pubB64 = Buffer.from(publicKey.export({ type: 'spki', format: 'der' })).toString('base64')

writeFileSync(privPath, privPem, { mode: 0o600 })
writeFileSync(pubPath, pubPem)
writeFileSync(b64Path, `${pubB64}\n`)

console.log('Wrote:')
console.log(`  ${privPath}`)
console.log(`  ${pubPath}`)
console.log(`  ${b64Path}`)
console.log('')
console.log('Paste into src/main/update-trust.ts:')
console.log(`export const UPDATE_MANIFEST_PUBLIC_KEY_SPKI_B64 =`)
console.log(`  '${pubB64}'`)
console.log('')
console.log('Store the private PEM as GitHub Actions secret UPDATE_SIGNING_PRIVATE_KEY.')
