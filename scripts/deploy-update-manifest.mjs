#!/usr/bin/env node
/**
 * Upload signed update manifests to the trust host (codemacher.de).
 *
 * Env (or flags):
 *   UPDATE_MANIFEST_DEPLOY_HOST   e.g. codemacher.de or SSH host alias
 *   UPDATE_MANIFEST_DEPLOY_USER   SSH user
 *   UPDATE_MANIFEST_DEPLOY_PATH   remote dir, e.g. /var/www/codemacher.de/public/dmarc-lighthouse/updates
 *   UPDATE_MANIFEST_DEPLOY_KEY    optional path to private key (default: ssh-agent / ~/.ssh)
 *   UPDATE_MANIFEST_DEPLOY_PORT   optional SSH port (default 22)
 *   DMARC_UPDATE_MANIFEST_BASE_URL  public base URL for --verify (default from update-trust)
 *
 * Usage:
 *   node scripts/deploy-update-manifest.mjs --dir dist-release [--version 1.0.16] [--verify]
 *   node scripts/deploy-update-manifest.mjs --dir dist-release --dry-run
 */
import { spawnSync } from 'node:child_process'
import { existsSync, readFileSync, mkdtempSync, writeFileSync, chmodSync, rmSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const htaccessSrc = join(root, 'scripts', 'update-manifest.htaccess')

function arg(name, fallback = undefined) {
  const i = process.argv.indexOf(name)
  if (i >= 0 && process.argv[i + 1] && !process.argv[i + 1].startsWith('--')) {
    return process.argv[i + 1]
  }
  return fallback
}

function hasFlag(name) {
  return process.argv.includes(name)
}

function die(msg, code = 1) {
  console.error(msg)
  process.exit(code)
}

function run(cmd, args, opts = {}) {
  const res = spawnSync(cmd, args, { stdio: 'inherit', encoding: 'utf8', ...opts })
  if (res.error) throw res.error
  if (res.status !== 0) die(`${cmd} failed with exit ${res.status}`)
}

function sshTarget() {
  const host = process.env.UPDATE_MANIFEST_DEPLOY_HOST?.trim() || arg('--host')
  const user = process.env.UPDATE_MANIFEST_DEPLOY_USER?.trim() || arg('--user')
  const path = process.env.UPDATE_MANIFEST_DEPLOY_PATH?.trim() || arg('--path')
  const key = process.env.UPDATE_MANIFEST_DEPLOY_KEY?.trim() || arg('--key')
  const port = process.env.UPDATE_MANIFEST_DEPLOY_PORT?.trim() || arg('--port', '22')
  if (!host || !user || !path) {
    die(`Missing deploy config.

Set:
  UPDATE_MANIFEST_DEPLOY_HOST
  UPDATE_MANIFEST_DEPLOY_USER
  UPDATE_MANIFEST_DEPLOY_PATH   # remote absolute dir for manifests
Optional:
  UPDATE_MANIFEST_DEPLOY_KEY    # SSH private key file (or PEM via CI secret written to a file)
  UPDATE_MANIFEST_DEPLOY_PORT

Example path on TYPO3/Apache:
  /var/www/codemacher.de/public/dmarc-lighthouse/updates
→ https://codemacher.de/dmarc-lighthouse/updates/{version}.json`)
  }
  return { host, user, path: path.replace(/\/+$/, ''), key, port }
}

function sshArgs(cfg) {
  const args = ['-p', String(cfg.port), '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=accept-new']
  if (cfg.key) args.push('-i', cfg.key)
  return args
}

const dir = arg('--dir')
if (!dir) {
  die('Usage: deploy-update-manifest.mjs --dir <dir> [--version x.y.z] [--verify] [--dry-run]')
}

const pkg = require(join(root, 'package.json'))
const version = arg('--version', pkg.version)
const dryRun = hasFlag('--dry-run')
const doVerify = hasFlag('--verify')

const jsonPath = join(dir, `${version}.json`)
const sigPath = join(dir, `${version}.json.sig`)
if (!existsSync(jsonPath) || !existsSync(sigPath)) {
  die(`Missing ${jsonPath} and/or ${sigPath}\nRun: npm run update:sign -- --dir ${dir}`)
}

const cfg = sshTarget()
const remote = `${cfg.user}@${cfg.host}:${cfg.path}/`
const baseUrl = (
  process.env.DMARC_UPDATE_MANIFEST_BASE_URL?.trim() ||
  'https://codemacher.de/dmarc-lighthouse/updates'
).replace(/\/+$/, '')

console.log(`Deploy update manifest ${version}`)
console.log(`  local:  ${jsonPath}`)
console.log(`  local:  ${sigPath}`)
console.log(`  remote: ${remote}`)
console.log(`  public: ${baseUrl}/${version}.json`)

if (dryRun) {
  console.log('Dry-run: no files uploaded.')
  process.exit(0)
}

// If KEY is a PEM body (CI secret) rather than a path, write a temp key file.
let keyCleanup = null
if (cfg.key && cfg.key.includes('BEGIN')) {
  const tmp = mkdtempSync(join(tmpdir(), 'dmarc-deploy-'))
  const keyFile = join(tmp, 'key')
  writeFileSync(keyFile, cfg.key.endsWith('\n') ? cfg.key : `${cfg.key}\n`, { mode: 0o600 })
  chmodSync(keyFile, 0o600)
  cfg.key = keyFile
  keyCleanup = () => rmSync(tmp, { recursive: true, force: true })
} else if (cfg.key && !existsSync(cfg.key)) {
  die(`SSH key file not found: ${cfg.key}`)
}

function scpArgs(c) {
  const args = ['-P', String(c.port), '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=accept-new']
  if (c.key) args.push('-i', c.key)
  return args
}

try {
  const remoteDirShell = cfg.path.replace(/'/g, `'\\''`)
  run('ssh', [...sshArgs(cfg), `${cfg.user}@${cfg.host}`, `mkdir -p '${remoteDirShell}'`])
  run('scp', [...scpArgs(cfg), jsonPath, sigPath, remote])
  if (existsSync(htaccessSrc)) {
    run('scp', [...scpArgs(cfg), htaccessSrc, `${remote}.htaccess`])
  }
  console.log('Upload complete.')
} finally {
  keyCleanup?.()
}

if (doVerify) {
  const jsonUrl = `${baseUrl}/${version}.json`
  const sigUrl = `${baseUrl}/${version}.json.sig`
  console.log(`Verifying ${jsonUrl} …`)
  for (const url of [jsonUrl, sigUrl]) {
    const res = spawnSync('curl', ['-fsSL', '-o', '/dev/null', '-w', '%{http_code}', url], {
      encoding: 'utf8'
    })
    const code = (res.stdout || '').trim()
    if (res.status !== 0 || code !== '200') {
      die(`Verify failed for ${url} (HTTP ${code || 'error'}). Check webroot path / TYPO3 rewrite.`)
    }
    console.log(`  OK ${url}`)
  }
  const localBody = readFileSync(jsonPath, 'utf8')
  const remoteBody = spawnSync('curl', ['-fsSL', jsonUrl], { encoding: 'utf8' })
  if (remoteBody.status !== 0 || remoteBody.stdout !== localBody) {
    die('Remote JSON does not match local file.')
  }
  console.log('Remote manifest matches local bytes.')
}
