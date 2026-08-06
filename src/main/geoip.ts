import { app } from 'electron'
import { createWriteStream, existsSync, mkdirSync, unlinkSync, copyFileSync, mkdtempSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { pipeline } from 'stream/promises'
import { Readable } from 'stream'
import { x as tarExtract } from 'tar'
import maxmind, { type CityResponse, type AsnResponse, type Reader } from 'maxmind'
import type { GeoLiteDownloadResult, GeoLiteStatus, GeoSource } from '../shared/types'
import { t } from '../shared/i18n'
import { readdirSync } from 'fs'

export interface GeoLookupResult {
  country: string | null
  countryCode: string | null
  city: string | null
  lat: number | null
  lon: number | null
  asn: number | null
  asOrg: string | null
  geoSource: GeoSource
}

let cityReader: Reader<CityResponse> | null = null
let asnReader: Reader<AsnResponse> | null = null
let readersLoadedForDir: string | null = null

export function enrichmentDir(): string {
  const dir = join(app.getPath('userData'), 'enrichment')
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
  return dir
}

function cityDbPath(): string {
  return join(enrichmentDir(), 'GeoLite2-City.mmdb')
}

function asnDbPath(): string {
  return join(enrichmentDir(), 'GeoLite2-ASN.mmdb')
}

export function getGeoLiteStatus(): GeoLiteStatus {
  return {
    cityDb: existsSync(cityDbPath()),
    asnDb: existsSync(asnDbPath()),
    dir: enrichmentDir()
  }
}

async function ensureReaders(): Promise<void> {
  const dir = enrichmentDir()
  if (readersLoadedForDir === dir && (cityReader || asnReader)) return

  cityReader = null
  asnReader = null
  readersLoadedForDir = dir

  if (existsSync(cityDbPath())) {
    try {
      cityReader = await maxmind.open<CityResponse>(cityDbPath())
    } catch {
      cityReader = null
    }
  }
  if (existsSync(asnDbPath())) {
    try {
      asnReader = await maxmind.open<AsnResponse>(asnDbPath())
    } catch {
      asnReader = null
    }
  }
}

/** Reload mmdb readers after a download. */
export async function reloadGeoLiteReaders(): Promise<void> {
  readersLoadedForDir = null
  cityReader = null
  asnReader = null
  await ensureReaders()
}

function lookupMaxmind(ip: string): GeoLookupResult | null {
  if (!cityReader && !asnReader) return null
  let country: string | null = null
  let countryCode: string | null = null
  let city: string | null = null
  let lat: number | null = null
  let lon: number | null = null
  let asn: number | null = null
  let asOrg: string | null = null

  try {
    if (cityReader) {
      const r = cityReader.get(ip)
      if (r) {
        country = r.country?.names?.en ?? r.registered_country?.names?.en ?? null
        countryCode = r.country?.iso_code ?? r.registered_country?.iso_code ?? null
        city = r.city?.names?.en ?? null
        const la = r.location?.latitude
        const lo = r.location?.longitude
        lat = typeof la === 'number' && Number.isFinite(la) ? la : null
        lon = typeof lo === 'number' && Number.isFinite(lo) ? lo : null
      }
    }
  } catch {
    // ignore bad IP
  }

  try {
    if (asnReader) {
      const r = asnReader.get(ip)
      if (r) {
        asn = r.autonomous_system_number ?? null
        asOrg = r.autonomous_system_organization ?? null
      }
    }
  } catch {
    // ignore
  }

  if (!country && !countryCode && !city && lat == null && lon == null && asn == null && !asOrg) {
    return null
  }
  return { country, countryCode, city, lat, lon, asn, asOrg, geoSource: 'maxmind' }
}

async function lookupOnline(ip: string): Promise<GeoLookupResult | null> {
  try {
    const res = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`, {
      signal: AbortSignal.timeout(5000)
    })
    if (!res.ok) return null
    const data = (await res.json()) as {
      success?: boolean
      country?: string
      country_code?: string
      city?: string
      latitude?: number
      longitude?: number
      connection?: { asn?: number; org?: string }
    }
    if (data.success === false) return null
    const asn =
      typeof data.connection?.asn === 'number' && Number.isFinite(data.connection.asn)
        ? data.connection.asn
        : null
    return {
      country: data.country ?? null,
      countryCode: data.country_code ?? null,
      city: data.city ?? null,
      lat: typeof data.latitude === 'number' && Number.isFinite(data.latitude) ? data.latitude : null,
      lon:
        typeof data.longitude === 'number' && Number.isFinite(data.longitude)
          ? data.longitude
          : null,
      asn,
      asOrg: data.connection?.org ?? null,
      geoSource: 'online'
    }
  } catch {
    return null
  }
}

const emptyGeo = (): GeoLookupResult => ({
  country: null,
  countryCode: null,
  city: null,
  lat: null,
  lon: null,
  asn: null,
  asOrg: null,
  geoSource: 'none'
})

/** Hybrid GeoIP: MaxMind local first, optional online fallback. */
export async function lookupGeo(
  ip: string,
  options: { onlineFallback: boolean }
): Promise<GeoLookupResult> {
  await ensureReaders()
  const local = lookupMaxmind(ip)
  if (local) return local
  if (options.onlineFallback) {
    const online = await lookupOnline(ip)
    if (online) return online
  }
  return emptyGeo()
}

function findMmdb(dir: string): string | null {
  const entries = readdirSync(dir, { withFileTypes: true })
  for (const e of entries) {
    const full = join(dir, e.name)
    if (e.isDirectory()) {
      const nested = findMmdb(full)
      if (nested) return nested
    } else if (e.name.endsWith('.mmdb')) {
      return full
    }
  }
  return null
}

async function downloadAndExtractEdition(
  licenseKey: string,
  editionId: string,
  targetFile: string
): Promise<void> {
  const url =
    `https://download.maxmind.com/app/geoip_download?edition_id=${editionId}` +
    `&license_key=${encodeURIComponent(licenseKey)}&suffix=tar.gz`
  const res = await fetch(url, { signal: AbortSignal.timeout(120_000) })
  if (!res.ok || !res.body) {
    throw new Error(`MaxMind download failed (${res.status}) for ${editionId}`)
  }

  const workDir = mkdtempSync(join(tmpdir(), `dmarc-lighthouse-${editionId}-`))
  const archivePath = join(workDir, `${editionId}.tar.gz`)
  const nodeReadable = Readable.fromWeb(res.body as import('stream/web').ReadableStream)
  await pipeline(nodeReadable, createWriteStream(archivePath))

  await tarExtract({
    file: archivePath,
    cwd: workDir,
    gzip: true,
    // Reject path traversal / absolute paths from a compromised archive.
    filter: (p: string) => !p.includes('..') && !p.startsWith('/') && !p.includes('\\')
  })
  const mmdb = findMmdb(workDir)
  if (!mmdb) throw new Error(`No .mmdb found in ${editionId} archive`)
  copyFileSync(mmdb, targetFile)
  try {
    unlinkSync(archivePath)
  } catch {
    // ignore
  }
}

/** Download GeoLite2 City + ASN into userData/enrichment. */
export async function downloadGeoLite(licenseKey: string): Promise<GeoLiteDownloadResult> {
  const key = licenseKey.trim()
  if (!key) {
    return { ok: false, message: t('enrichment.maxmindKeyMissing') }
  }
  try {
    enrichmentDir()
    await downloadAndExtractEdition(key, 'GeoLite2-City', cityDbPath())
    await downloadAndExtractEdition(key, 'GeoLite2-ASN', asnDbPath())
    await reloadGeoLiteReaders()
    return { ok: true, message: t('enrichment.geoLiteDownloaded') }
  } catch (err) {
    return {
      ok: false,
      message: err instanceof Error ? err.message : String(err)
    }
  }
}
