import { generateKeyPairSync, sign } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import {
  matchDownloadedFile,
  parseUpdateManifest,
  serializeUpdateManifest,
  verifyDownloadedUpdate,
  verifyManifestSignature
} from '../src/main/update-manifest'
import { UPDATE_MANIFEST_PRODUCT } from '../src/main/update-trust'

function keyPair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519')
  const publicKeySpkiB64 = Buffer.from(
    publicKey.export({ type: 'spki', format: 'der' })
  ).toString('base64')
  return { privateKey, publicKeySpkiB64 }
}

describe('update-manifest', () => {
  it('round-trips canonical serialization and signature', () => {
    const { privateKey, publicKeySpkiB64 } = keyPair()
    const manifest = {
      schemaVersion: 1 as const,
      product: UPDATE_MANIFEST_PRODUCT,
      version: '1.2.3',
      files: [
        { name: 'dmarc-lighthouse-1.2.3-linux.AppImage', sha512: 'abc=' },
        { name: 'dmarc-lighthouse-1.2.3-win-setup.exe', sha512: 'def=' }
      ]
    }
    const body = serializeUpdateManifest(manifest)
    const sig = sign(null, Buffer.from(body, 'utf8'), privateKey).toString('base64')
    expect(verifyManifestSignature(body, sig, publicKeySpkiB64)).toBe(true)
    expect(verifyManifestSignature(body + ' ', sig, publicKeySpkiB64)).toBe(false)
    expect(parseUpdateManifest(body)).toEqual({
      ...manifest,
      files: [...manifest.files].sort((a, b) => a.name.localeCompare(b.name))
    })
  })

  it('matches downloaded file against signed manifest hashes', () => {
    const sha = 'base64sha512value=='
    const manifest = {
      schemaVersion: 1 as const,
      product: UPDATE_MANIFEST_PRODUCT,
      version: '1.0.16',
      files: [{ name: 'dmarc-lighthouse-1.0.16-win-setup.exe', sha512: sha }]
    }
    const ok = matchDownloadedFile(manifest, {
      version: '1.0.16',
      downloadedFile: '/tmp/cache/dmarc-lighthouse-1.0.16-win-setup.exe',
      files: [
        {
          url: 'https://github.com/x/y/releases/download/v1.0.16/dmarc-lighthouse-1.0.16-win-setup.exe',
          sha512: sha
        }
      ],
      sha512: sha,
      path: 'dmarc-lighthouse-1.0.16-win-setup.exe'
    })
    expect(ok.ok).toBe(true)

    const bad = matchDownloadedFile(manifest, {
      version: '1.0.16',
      downloadedFile: '/tmp/cache/dmarc-lighthouse-1.0.16-win-setup.exe',
      files: [
        {
          url: 'https://example.com/dmarc-lighthouse-1.0.16-win-setup.exe',
          sha512: 'tampered=='
        }
      ],
      sha512: 'tampered==',
      path: 'dmarc-lighthouse-1.0.16-win-setup.exe'
    })
    expect(bad.ok).toBe(false)
  })

  it('verifyDownloadedUpdate fetches trust-host files and rejects bad signatures', async () => {
    const { privateKey, publicKeySpkiB64 } = keyPair()
    const sha = 'goodhash=='
    const body = serializeUpdateManifest({
      schemaVersion: 1,
      product: UPDATE_MANIFEST_PRODUCT,
      version: '9.9.9',
      files: [{ name: 'dmarc-lighthouse-9.9.9-linux.AppImage', sha512: sha }]
    })
    const goodSig = sign(null, Buffer.from(body, 'utf8'), privateKey).toString('base64')
    const { privateKey: otherKey } = generateKeyPairSync('ed25519')
    const badSig = sign(null, Buffer.from(body, 'utf8'), otherKey).toString('base64')

    const info = {
      version: '9.9.9',
      downloadedFile: '/tmp/dmarc-lighthouse-9.9.9-linux.AppImage',
      files: [{ url: 'dmarc-lighthouse-9.9.9-linux.AppImage', sha512: sha }],
      sha512: sha,
      path: 'dmarc-lighthouse-9.9.9-linux.AppImage',
      releaseDate: '2026-01-01'
    }

    const store = new Map([
      ['https://trust.example/updates/9.9.9.json', body],
      ['https://trust.example/updates/9.9.9.json.sig', `${goodSig}\n`]
    ])

    const ok = await verifyDownloadedUpdate(info, {
      publicKeySpkiB64,
      baseUrl: 'https://trust.example/updates',
      fetchText: async (url) => {
        const v = store.get(url)
        if (v == null) throw new Error(`missing ${url}`)
        return v
      }
    })
    expect(ok.ok).toBe(true)

    store.set('https://trust.example/updates/9.9.9.json.sig', `${badSig}\n`)
    const rejected = await verifyDownloadedUpdate(info, {
      publicKeySpkiB64,
      baseUrl: 'https://trust.example/updates',
      fetchText: async (url) => store.get(url) ?? ''
    })
    expect(rejected).toEqual({ ok: false, reason: 'Manifest-Signatur ungültig' })
  })
})
