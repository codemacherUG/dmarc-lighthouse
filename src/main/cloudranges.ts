import { app } from 'electron'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs'
import { join } from 'path'
import { matchCloudProvider, parseCidr, type CloudPrefix } from '../shared/ipcidr'
import { appFetch } from './http'

export type { CloudPrefix }
export { matchCloudProvider, parseCidr }

interface StoredRanges {
  updatedAt: string
  prefixes: CloudPrefix[]
}

const ONE_DAY_MS = 24 * 60 * 60 * 1000

let memory: StoredRanges | null = null
let loadPromise: Promise<void> | null = null

function enrichmentDir(): string {
  const dir = join(app.getPath('userData'), 'enrichment')
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
  return dir
}

function rangesPath(): string {
  return join(enrichmentDir(), 'cloud-ranges.json')
}

async function fetchText(url: string): Promise<string> {
  const res = await appFetch(url, { signal: AbortSignal.timeout(30_000) })
  if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`)
  return res.text()
}

async function fetchJson<T>(url: string): Promise<T> {
  const text = await fetchText(url)
  return JSON.parse(text) as T
}

async function loadAws(prefixes: CloudPrefix[]): Promise<void> {
  const data = await fetchJson<{
    prefixes?: Array<{ ip_prefix?: string; service?: string }>
    ipv6_prefixes?: Array<{ ipv6_prefix?: string; service?: string }>
  }>('https://ip-ranges.amazonaws.com/ip-ranges.json')
  for (const p of data.prefixes ?? []) {
    if (!p.ip_prefix) continue
    const provider = /SES|EMAIL/i.test(p.service ?? '') ? 'Amazon SES' : 'Amazon AWS'
    const entry = parseCidr(provider, p.ip_prefix)
    if (entry) prefixes.push(entry)
  }
  for (const p of data.ipv6_prefixes ?? []) {
    if (!p.ipv6_prefix) continue
    const entry = parseCidr('Amazon AWS', p.ipv6_prefix)
    if (entry) prefixes.push(entry)
  }
}

async function loadGoogle(prefixes: CloudPrefix[]): Promise<void> {
  for (const url of [
    'https://www.gstatic.com/ipranges/goog.json',
    'https://www.gstatic.com/ipranges/cloud.json'
  ]) {
    const data = await fetchJson<{
      prefixes?: Array<{ ipv4Prefix?: string; ipv6Prefix?: string }>
    }>(url)
    for (const p of data.prefixes ?? []) {
      if (p.ipv4Prefix) {
        const entry = parseCidr('Google', p.ipv4Prefix)
        if (entry) prefixes.push(entry)
      }
      if (p.ipv6Prefix) {
        const entry = parseCidr('Google', p.ipv6Prefix)
        if (entry) prefixes.push(entry)
      }
    }
  }
}

async function loadCloudflare(prefixes: CloudPrefix[]): Promise<void> {
  const v4 = await fetchText('https://www.cloudflare.com/ips-v4')
  for (const line of v4.split(/\r?\n/)) {
    const cidr = line.trim()
    if (!cidr) continue
    const entry = parseCidr('Cloudflare', cidr)
    if (entry) prefixes.push(entry)
  }
  try {
    const v6 = await fetchText('https://www.cloudflare.com/ips-v6')
    for (const line of v6.split(/\r?\n/)) {
      const cidr = line.trim()
      if (!cidr) continue
      const entry = parseCidr('Cloudflare', cidr)
      if (entry) prefixes.push(entry)
    }
  } catch {
    // IPv6 list optional
  }
}

async function refreshRanges(): Promise<StoredRanges> {
  const prefixes: CloudPrefix[] = []
  const errors: string[] = []
  await Promise.all([
    loadAws(prefixes).catch((e) => errors.push(`AWS: ${e instanceof Error ? e.message : e}`)),
    loadGoogle(prefixes).catch((e) => errors.push(`Google: ${e instanceof Error ? e.message : e}`)),
    loadCloudflare(prefixes).catch((e) =>
      errors.push(`Cloudflare: ${e instanceof Error ? e.message : e}`)
    )
  ])
  if (prefixes.length === 0 && errors.length) {
    throw new Error(errors.join('; '))
  }
  const stored: StoredRanges = { updatedAt: new Date().toISOString(), prefixes }
  writeFileSync(rangesPath(), JSON.stringify(stored), 'utf8')
  memory = stored
  return stored
}

function readStored(): StoredRanges | null {
  const path = rangesPath()
  if (!existsSync(path)) return null
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as StoredRanges
  } catch {
    return null
  }
}

async function ensureLoaded(): Promise<void> {
  if (memory && Date.now() - Date.parse(memory.updatedAt) < ONE_DAY_MS) return
  if (loadPromise) return loadPromise

  loadPromise = (async () => {
    const stored = readStored()
    if (stored?.prefixes?.length) {
      memory = stored
      if (Date.now() - Date.parse(stored.updatedAt) < ONE_DAY_MS) return
    }
    try {
      await refreshRanges()
    } catch {
      if (!memory && stored) memory = stored
    }
  })().finally(() => {
    loadPromise = null
  })

  return loadPromise
}

/** Ensure prefix lists are available (cached ≤1 day) and match an IP. */
export async function lookupCloudProvider(ip: string): Promise<string | null> {
  try {
    await ensureLoaded()
  } catch {
    // continue with whatever is in memory
  }
  if (!memory?.prefixes?.length) return null
  return matchCloudProvider(ip, memory.prefixes)
}

/** Test helper: seed in-memory prefixes without network. */
export function setCloudRangesForTests(prefixes: CloudPrefix[]): void {
  memory = { updatedAt: new Date().toISOString(), prefixes }
}
