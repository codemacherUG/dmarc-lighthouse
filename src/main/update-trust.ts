/**
 * Trust anchors for auto-update manifests hosted outside GitHub.
 * Public key is Ed25519 SPKI (DER) base64 — pair with keys/update-ed25519-private.pem
 * (or GitHub secret UPDATE_SIGNING_PRIVATE_KEY). Rotate by shipping a new app build.
 */
export const UPDATE_MANIFEST_PRODUCT = 'dmarc-lighthouse'

/** Base URL without trailing slash. Override via DMARC_UPDATE_MANIFEST_BASE_URL for tests. */
export const UPDATE_MANIFEST_BASE_URL_DEFAULT =
  'https://codemacher.de/dmarc-lighthouse/updates'

/** Ed25519 public key (SPKI DER, base64). */
export const UPDATE_MANIFEST_PUBLIC_KEY_SPKI_B64 =
  'MCowBQYDK2VwAyEAWFzzNjGPQOpKrOn6FNJFq7ZDm8q2WzW31vji+IY4Iuo='

export function updateManifestBaseUrl(
  env: NodeJS.ProcessEnv = process.env
): string {
  const fromEnv = env.DMARC_UPDATE_MANIFEST_BASE_URL?.trim()
  return (fromEnv || UPDATE_MANIFEST_BASE_URL_DEFAULT).replace(/\/+$/, '')
}

export function updateManifestUrls(
  version: string,
  baseUrl = updateManifestBaseUrl()
): { jsonUrl: string; sigUrl: string } {
  const v = version.trim()
  return {
    jsonUrl: `${baseUrl}/${v}.json`,
    sigUrl: `${baseUrl}/${v}.json.sig`
  }
}
