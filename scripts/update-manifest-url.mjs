/** Public base URL for signed update manifests (no trailing slash). */
export const UPDATE_MANIFEST_BASE_URL = 'https://apps.codemacher.de/dmarc-lighthouse/updates'

/** Previous host — keep a 301 redirect so already-shipped apps still verify. */
export const UPDATE_MANIFEST_LEGACY_BASE_URL = 'https://codemacher.de/dmarc-lighthouse/updates'
