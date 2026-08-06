#!/usr/bin/env node
/**
 * Regenerates THIRD_PARTY_NOTICES.txt from production npm dependencies.
 * Run: npm run licenses:generate
 */
import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const outPath = join(root, 'THIRD_PARTY_NOTICES.txt')

const header = `THIRD-PARTY NOTICES
===================

DMARC Lighthouse includes open-source software and optional third-party data.
This file lists production npm dependency licenses bundled with the application.
Electron and Chromium license texts also ship beside the executable as
LICENSE.electron.txt and LICENSES.chromium.html.

-------------------------------------------------------------------------------
MaxMind GeoLite2 (optional offline GeoIP data)
-------------------------------------------------------------------------------
This product includes GeoLite2 Data created by MaxMind, available from
https://www.maxmind.com

GeoLite2 databases are downloaded by the end user with a MaxMind license key
and are not redistributed inside the application package. Use of GeoLite2 is
subject to the MaxMind GeoLite End User License Agreement:
https://www.maxmind.com/en/geolite/eula

`

function collectJson() {
  const out = execFileSync(
    process.platform === 'win32' ? 'npx.cmd' : 'npx',
    ['--yes', 'license-checker-rseidelsohn', '--production', '--json'],
    { cwd: root, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 }
  )
  return JSON.parse(out)
}

function readLicenseText(pkg) {
  const file = pkg.licenseFile
  if (!file || !existsSync(file)) return null
  try {
    const text = readFileSync(file, 'utf8').trim()
    if (!text) return null
    // Keep notices readable; full Chromium texts live elsewhere.
    if (text.length > 24_000) {
      return `${text.slice(0, 24_000)}\n\n… [truncated; see ${relative(root, file)}]`
    }
    return text
  } catch {
    return null
  }
}

const data = collectJson()
const entries = Object.entries(data)
  .filter(([name]) => !name.startsWith('dmarc-lighthouse@'))
  .sort(([a], [b]) => a.localeCompare(b))

const lines = [header]

for (const [name, pkg] of entries) {
  const license = pkg.licenses || 'UNKNOWN'
  const repo = pkg.repository || pkg.url || ''
  lines.push('-------------------------------------------------------------------------------')
  lines.push(name)
  lines.push(`License: ${license}`)
  if (repo) lines.push(`Repository: ${repo}`)
  lines.push('-------------------------------------------------------------------------------')
  const text = readLicenseText(pkg)
  lines.push(text || `(No license file found in package; SPDX/license field: ${license})`)
  lines.push('')
}

writeFileSync(outPath, `${lines.join('\n').trimEnd()}\n`, 'utf8')
console.log(`Wrote ${relative(root, outPath)} (${entries.length} packages)`)
