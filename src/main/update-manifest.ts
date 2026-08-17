import { createPublicKey, verify } from 'crypto'
import { basename } from 'path'
import type { UpdateDownloadedEvent } from 'electron-updater'
import {
  UPDATE_MANIFEST_PRODUCT,
  UPDATE_MANIFEST_PUBLIC_KEY_SPKI_B64,
  updateManifestUrls
} from './update-trust'

export interface UpdateManifestFile {
  name: string
  sha512: string
}

export interface UpdateManifest {
  schemaVersion: 1
  product: string
  version: string
  files: UpdateManifestFile[]
}

export type ManifestVerifyResult =
  | { ok: true; manifest: UpdateManifest }
  | { ok: false; reason: string }

function isNonEmptyString(v: unknown): v is string {
  return typeof v === 'string' && v.trim().length > 0
}

/** Parse and structurally validate a manifest JSON document. */
export function parseUpdateManifest(raw: string): UpdateManifest {
  let data: unknown
  try {
    data = JSON.parse(raw) as unknown
  } catch {
    throw new Error('Update-Manifest ist kein gültiges JSON')
  }
  if (!data || typeof data !== 'object') {
    throw new Error('Update-Manifest ungültig')
  }
  const obj = data as Record<string, unknown>
  if (obj.schemaVersion !== 1) {
    throw new Error('Update-Manifest: unbekannte schemaVersion')
  }
  if (!isNonEmptyString(obj.product) || !isNonEmptyString(obj.version)) {
    throw new Error('Update-Manifest: product/version fehlen')
  }
  if (!Array.isArray(obj.files) || obj.files.length === 0) {
    throw new Error('Update-Manifest: files fehlen')
  }
  const files: UpdateManifestFile[] = obj.files.map((entry, i) => {
    if (!entry || typeof entry !== 'object') {
      throw new Error(`Update-Manifest: files[${i}] ungültig`)
    }
    const f = entry as Record<string, unknown>
    if (!isNonEmptyString(f.name) || !isNonEmptyString(f.sha512)) {
      throw new Error(`Update-Manifest: files[${i}] name/sha512 fehlen`)
    }
    return { name: f.name.trim(), sha512: f.sha512.trim() }
  })
  return {
    schemaVersion: 1,
    product: obj.product.trim(),
    version: obj.version.trim(),
    files
  }
}

/** Build canonical JSON bytes for signing (stable key order, 2-space indent, trailing newline). */
export function serializeUpdateManifest(manifest: UpdateManifest): string {
  const files = [...manifest.files]
    .map((f) => ({ name: f.name, sha512: f.sha512 }))
    .sort((a, b) => a.name.localeCompare(b.name))
  const body = {
    schemaVersion: 1 as const,
    product: manifest.product,
    version: manifest.version,
    files
  }
  return `${JSON.stringify(body, null, 2)}\n`
}

export function verifyManifestSignature(
  manifestUtf8: string,
  signatureBase64: string,
  publicKeySpkiB64 = UPDATE_MANIFEST_PUBLIC_KEY_SPKI_B64
): boolean {
  const sig = signatureBase64.trim()
  if (!sig) return false
  let signature: Buffer
  try {
    signature = Buffer.from(sig, 'base64')
  } catch {
    return false
  }
  if (signature.length !== 64) return false
  try {
    const key = createPublicKey({
      key: Buffer.from(publicKeySpkiB64, 'base64'),
      format: 'der',
      type: 'spki'
    })
    return verify(null, Buffer.from(manifestUtf8, 'utf8'), key, signature)
  } catch {
    return false
  }
}

function fileUrlName(urlOrPath: string): string {
  try {
    if (/^https?:\/\//i.test(urlOrPath)) {
      return decodeURIComponent(basename(new URL(urlOrPath).pathname))
    }
  } catch {
    /* fall through */
  }
  return basename(urlOrPath)
}

/**
 * After electron-updater downloaded a file (and checked GitHub latest*.yml sha512),
 * require a matching entry in our externally signed manifest.
 */
export function matchDownloadedFile(
  manifest: UpdateManifest,
  info: Pick<UpdateDownloadedEvent, 'version' | 'files' | 'downloadedFile' | 'sha512' | 'path'>
): ManifestVerifyResult {
  if (manifest.product !== UPDATE_MANIFEST_PRODUCT) {
    return { ok: false, reason: `Unerwartetes product: ${manifest.product}` }
  }
  if (manifest.version !== info.version) {
    return {
      ok: false,
      reason: `Manifest-Version ${manifest.version} ≠ Update ${info.version}`
    }
  }

  const downloadedName = fileUrlName(info.downloadedFile)
  const candidates = new Map<string, string>()
  for (const f of info.files ?? []) {
    candidates.set(fileUrlName(f.url), f.sha512)
  }
  if (info.path) candidates.set(fileUrlName(info.path), info.sha512)
  // Prefer hash reported for the exact downloaded basename; else first file.
  const reportedSha =
    candidates.get(downloadedName) ??
    info.files?.[0]?.sha512 ??
    info.sha512
  if (!reportedSha) {
    return { ok: false, reason: 'Keine sha512 vom Updater für die Datei' }
  }

  const entry =
    manifest.files.find((f) => f.name === downloadedName) ??
    manifest.files.find((f) => candidates.has(f.name) && f.sha512 === reportedSha)

  if (!entry) {
    return {
      ok: false,
      reason: `Datei ${downloadedName} fehlt im signierten Manifest`
    }
  }
  if (entry.sha512 !== reportedSha) {
    return {
      ok: false,
      reason: `sha512 stimmt nicht mit signiertem Manifest überein (${downloadedName})`
    }
  }
  return { ok: true, manifest }
}

export type FetchText = (url: string) => Promise<string>

async function defaultFetchText(url: string): Promise<string> {
  const { appFetch } = await import('./http')
  const res = await appFetch(url, {
    headers: { Accept: 'application/octet-stream, application/json, text/plain, */*' },
    signal: AbortSignal.timeout(20_000),
    redirect: 'follow'
  })
  if (!res.ok) {
    throw new Error(`HTTP ${res.status} für ${url}`)
  }
  return await res.text()
}

/** Fetch manifest + detached signature from the trust host and validate against the download. */
export async function verifyDownloadedUpdate(
  info: UpdateDownloadedEvent,
  opts?: {
    fetchText?: FetchText
    publicKeySpkiB64?: string
    baseUrl?: string
  }
): Promise<ManifestVerifyResult> {
  const { jsonUrl, sigUrl } = updateManifestUrls(info.version, opts?.baseUrl)
  const fetchText = opts?.fetchText ?? defaultFetchText

  let manifestUtf8: string
  let sigText: string
  try {
    ;[manifestUtf8, sigText] = await Promise.all([fetchText(jsonUrl), fetchText(sigUrl)])
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    return { ok: false, reason: `Manifest nicht ladbar: ${message}` }
  }

  if (!verifyManifestSignature(manifestUtf8, sigText, opts?.publicKeySpkiB64)) {
    return { ok: false, reason: 'Manifest-Signatur ungültig' }
  }

  let manifest: UpdateManifest
  try {
    manifest = parseUpdateManifest(manifestUtf8)
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    return { ok: false, reason: message }
  }

  // Published bytes must match canonical serialization so CI and app agree.
  if (manifestUtf8 !== serializeUpdateManifest(manifest)) {
    return {
      ok: false,
      reason: 'Manifest weicht von kanonischer Serialisierung ab'
    }
  }

  return matchDownloadedFile(manifest, info)
}
