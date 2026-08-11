#!/usr/bin/env node
/**
 * Build and Ed25519-sign an update manifest for files in a release directory.
 *
 * Usage:
 *   node scripts/sign-update-manifest.mjs --dir dist-release [--version 1.0.16] [--out dist-release]
 *
 * Private key: UPDATE_SIGNING_PRIVATE_KEY (PEM) or keys/update-ed25519-private.pem
 */
import { createHash, createPrivateKey, sign } from 'node:crypto'
import { readdirSync, readFileSync, writeFileSync, statSync, existsSync } from 'node:fs'
import { join, dirname, basename } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const root = join(dirname(fileURLToPath(import.meta.url)), '..')

const ARTIFACT_RE =
  /\.(exe|dmg|zip|AppImage|deb|yml|blockmap)$/i
const SKIP_NAMES = new Set(['latest.yml', 'latest-linux.yml', 'latest-mac.yml'])

function arg(name, fallback = undefined) {
  const i = process.argv.indexOf(name)
  if (i >= 0 && process.argv[i + 1]) return process.argv[i + 1]
  return fallback
}

function loadPrivateKey() {
  const fromEnv = process.env.UPDATE_SIGNING_PRIVATE_KEY?.trim()
  if (fromEnv) {
    return createPrivateKey(fromEnv.includes('BEGIN') ? fromEnv : Buffer.from(fromEnv, 'base64').toString('utf8'))
  }
  const path = join(root, 'keys', 'update-ed25519-private.pem')
  if (!existsSync(path)) {
    throw new Error(
      'Missing private key: set UPDATE_SIGNING_PRIVATE_KEY or create keys/update-ed25519-private.pem'
    )
  }
  return createPrivateKey(readFileSync(path, 'utf8'))
}

function serializeManifest(manifest) {
  const files = [...manifest.files]
    .map((f) => ({ name: f.name, sha512: f.sha512 }))
    .sort((a, b) => a.name.localeCompare(b.name))
  return `${JSON.stringify(
    {
      schemaVersion: 1,
      product: manifest.product,
      version: manifest.version,
      files
    },
    null,
    2
  )}\n`
}

const dir = arg('--dir')
if (!dir) {
  console.error('Usage: sign-update-manifest.mjs --dir <release-dir> [--version x.y.z] [--out <dir>]')
  process.exit(1)
}

const pkg = require(join(root, 'package.json'))
const version = arg('--version', pkg.version)
const outDir = arg('--out', dir)

const names = readdirSync(dir).filter((name) => {
  if (SKIP_NAMES.has(name)) return false
  if (name.endsWith('.json') || name.endsWith('.sig')) return false
  if (!ARTIFACT_RE.test(name)) return false
  // Only hash installable packages that auto-update cares about (+ keep all hashed for transparency)
  return !name.endsWith('.blockmap') && !name.endsWith('.yml')
})

if (names.length === 0) {
  console.error(`No artifact files found in ${dir}`)
  process.exit(1)
}

const files = names
  .map((name) => {
    const full = join(dir, name)
    if (!statSync(full).isFile()) return null
    const sha512 = createHash('sha512').update(readFileSync(full)).digest('base64')
    return { name, sha512 }
  })
  .filter(Boolean)

const manifest = {
  schemaVersion: 1,
  product: 'dmarc-lighthouse',
  version,
  files
}

const body = serializeManifest(manifest)
const privateKey = loadPrivateKey()
const signature = sign(null, Buffer.from(body, 'utf8'), privateKey)
const sigB64 = signature.toString('base64')

const jsonPath = join(outDir, `${version}.json`)
const sigPath = join(outDir, `${version}.json.sig`)
writeFileSync(jsonPath, body)
writeFileSync(sigPath, `${sigB64}\n`)

console.log(`Signed update manifest for ${version}`)
console.log(`  ${jsonPath}`)
console.log(`  ${sigPath}`)
console.log(`  files: ${files.map((f) => f.name).join(', ')}`)
console.log('')
console.log(`Deploy to trust host (not GitHub Release):`)
console.log(`  https://codemacher.de/dmarc-lighthouse/updates/${basename(jsonPath)}`)
console.log(`  https://codemacher.de/dmarc-lighthouse/updates/${basename(sigPath)}`)
