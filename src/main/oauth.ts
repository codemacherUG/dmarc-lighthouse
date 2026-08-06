import { createHash, randomBytes } from 'crypto'
import { createServer } from 'http'
import type { OAuthProvider } from '../shared/types'
import { t } from '../shared/i18n'
import { openExternalSafe } from './open-external'

export interface OAuthTokens {
  accessToken: string
  refreshToken: string
  expiresAt: number
  email: string
}

export interface OAuthClientConfig {
  googleClientId: string
  microsoftClientId: string
}

interface ProviderEndpoints {
  authorizeUrl: string
  tokenUrl: string
  scopes: string[]
  clientId: string
}

function base64Url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

function pkcePair(): { verifier: string; challenge: string } {
  const verifier = base64Url(randomBytes(32))
  const challenge = base64Url(createHash('sha256').update(verifier).digest())
  return { verifier, challenge }
}

function endpoints(provider: OAuthProvider, config: OAuthClientConfig): ProviderEndpoints {
  if (provider === 'google') {
    const clientId = config.googleClientId.trim()
    if (!clientId) throw new Error(t('oauth.missingGoogleClientId'))
    return {
      authorizeUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
      tokenUrl: 'https://oauth2.googleapis.com/token',
      scopes: ['https://mail.google.com/', 'openid', 'email'],
      clientId
    }
  }
  const clientId = config.microsoftClientId.trim()
  if (!clientId) throw new Error(t('oauth.missingMicrosoftClientId'))
  return {
    authorizeUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
    tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
    scopes: [
      'offline_access',
      'openid',
      'email',
      'https://outlook.office.com/IMAP.AccessAsUser.All'
    ],
    clientId
  }
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

function htmlPage(title: string, body: string): string {
  const safeTitle = escapeHtml(title)
  const safeBody = escapeHtml(body)
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"/><title>${safeTitle}</title>
<style>body{font-family:system-ui,sans-serif;max-width:32rem;margin:3rem auto;padding:0 1rem;line-height:1.5}
h1{font-size:1.25rem}</style></head><body><h1>${safeTitle}</h1><p>${safeBody}</p></body></html>`
}

async function startLoopback(): Promise<{
  redirectUri: string
  state: string
  wait: () => Promise<string>
  close: () => void
}> {
  const state = base64Url(randomBytes(16))
  let settle: ((code: string) => void) | null = null
  let fail: ((err: Error) => void) | null = null
  const codePromise = new Promise<string>((resolve, reject) => {
    settle = resolve
    fail = reject
  })

  const server = createServer((req, res) => {
    try {
      const url = new URL(req.url ?? '/', 'http://127.0.0.1')
      if (url.pathname !== '/oauth/callback') {
        res.writeHead(404)
        res.end('Not found')
        return
      }
      const err = url.searchParams.get('error_description') || url.searchParams.get('error')
      if (err) {
        res.writeHead(400, { 'Content-Type': 'text/html; charset=utf-8' })
        res.end(htmlPage('OAuth error', err))
        fail?.(new Error(err))
        server.close()
        return
      }
      const returnedState = url.searchParams.get('state')
      const code = url.searchParams.get('code')
      if (!code || returnedState !== state) {
        res.writeHead(400, { 'Content-Type': 'text/html; charset=utf-8' })
        res.end(htmlPage('OAuth error', 'Invalid state or missing code'))
        fail?.(new Error(t('oauth.invalidCallback')))
        server.close()
        return
      }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
      res.end(htmlPage(t('oauth.successTitle'), t('oauth.successBody')))
      settle?.(code)
      setTimeout(() => {
        try {
          server.close()
        } catch {
          // ignore
        }
      }, 300)
    } catch (e) {
      fail?.(e instanceof Error ? e : new Error(String(e)))
      try {
        server.close()
      } catch {
        // ignore
      }
    }
  })

  // Fixed loopback port so Google/Microsoft redirect URIs can be registered once.
  const port = 17893
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(port, '127.0.0.1', () => resolve())
  })

  const redirectUri = `http://127.0.0.1:${port}/oauth/callback`

  const timer = setTimeout(() => {
    fail?.(new Error(t('oauth.timeout')))
    try {
      server.close()
    } catch {
      // ignore
    }
  }, 5 * 60_000)

  return {
    redirectUri,
    state,
    wait: async () => {
      try {
        return await codePromise
      } finally {
        clearTimeout(timer)
      }
    },
    close: () => {
      clearTimeout(timer)
      try {
        server.close()
      } catch {
        // ignore
      }
    }
  }
}

async function exchangeToken(
  tokenUrl: string,
  body: Record<string, string>
): Promise<Record<string, unknown>> {
  const res = await fetch(tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(body).toString()
  })
  const json = (await res.json()) as Record<string, unknown>
  if (!res.ok) {
    const desc = String(json.error_description ?? json.error ?? res.statusText)
    throw new Error(desc)
  }
  return json
}

async function fetchEmail(provider: OAuthProvider, accessToken: string): Promise<string> {
  if (provider === 'google') {
    const res = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
      headers: { Authorization: `Bearer ${accessToken}` }
    })
    const json = (await res.json()) as { email?: string }
    if (!res.ok || !json.email) throw new Error(t('oauth.emailMissing'))
    return json.email
  }
  const res = await fetch('https://graph.microsoft.com/oidc/userinfo', {
    headers: { Authorization: `Bearer ${accessToken}` }
  })
  if (res.ok) {
    const json = (await res.json()) as { email?: string; preferred_username?: string }
    const email = json.email || json.preferred_username
    if (email) return email
  }
  throw new Error(t('oauth.emailMissing'))
}

function toTokens(
  json: Record<string, unknown>,
  email: string,
  previousRefresh?: string
): OAuthTokens {
  const accessToken = String(json.access_token ?? '')
  if (!accessToken) throw new Error(t('oauth.tokenMissing'))
  const refreshToken = String(json.refresh_token ?? previousRefresh ?? '')
  if (!refreshToken) throw new Error(t('oauth.refreshMissing'))
  const expiresIn = Number(json.expires_in ?? 3600)
  return {
    accessToken,
    refreshToken,
    expiresAt: Date.now() + Math.max(60, expiresIn) * 1000 - 60_000,
    email
  }
}

/** Interactive browser login (authorization code + PKCE via loopback). */
export async function authorizeInteractive(
  provider: OAuthProvider,
  config: OAuthClientConfig
): Promise<OAuthTokens> {
  const ep = endpoints(provider, config)
  const { verifier, challenge } = pkcePair()
  const loop = await startLoopback()
  try {
    const url = new URL(ep.authorizeUrl)
    url.searchParams.set('client_id', ep.clientId)
    url.searchParams.set('response_type', 'code')
    url.searchParams.set('redirect_uri', loop.redirectUri)
    url.searchParams.set('scope', ep.scopes.join(' '))
    url.searchParams.set('state', loop.state)
    url.searchParams.set('code_challenge', challenge)
    url.searchParams.set('code_challenge_method', 'S256')
    if (provider === 'google') {
      url.searchParams.set('access_type', 'offline')
      url.searchParams.set('prompt', 'consent')
    } else {
      url.searchParams.set('response_mode', 'query')
    }

    await openExternalSafe(url.toString())
    const code = await loop.wait()
    const json = await exchangeToken(ep.tokenUrl, {
      client_id: ep.clientId,
      grant_type: 'authorization_code',
      code,
      redirect_uri: loop.redirectUri,
      code_verifier: verifier
    })
    let email = ''
    try {
      email = await fetchEmail(provider, String(json.access_token ?? ''))
    } catch {
      email = ''
    }
    return toTokens(json, email)
  } finally {
    loop.close()
  }
}

/** Refresh an access token using the stored refresh token. */
export async function refreshAccessToken(
  provider: OAuthProvider,
  config: OAuthClientConfig,
  refreshToken: string,
  email: string
): Promise<OAuthTokens> {
  const ep = endpoints(provider, config)
  const json = await exchangeToken(ep.tokenUrl, {
    client_id: ep.clientId,
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    scope: ep.scopes.join(' ')
  })
  return toTokens(json, email, refreshToken)
}

export function oauthProviderForAccount(
  provider: 'gmail' | 'outlook' | 'microsoft' | 'custom'
): OAuthProvider | null {
  if (provider === 'gmail') return 'google'
  if (provider === 'outlook' || provider === 'microsoft') return 'microsoft'
  return null
}
